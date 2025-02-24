import {
    AuthConfig,
    AuthTokens,
    CookieOptions,
    Endpoints,
    ILogger,
    IRequest,
    IResponse,
    LoginResponse,
    PollResponse,
    TokenData,
    UserActive,
    UserCredits
} from './types';
import {HttpClient} from './utils/HttpClient';
import {AuthTokenError} from './exceptions/AuthTokenError';

/**
 * Service for handling authentication tokens and user credentials
 * @class ConnectService
 */
export class ConnectService {
    private readonly cookieName = 'connect.se';

    private static readonly VERSION = '1.0.0';

    private readonly config: AuthConfig;
    private readonly httpClient: HttpClient;
    private readonly logger: ILogger;
    private requestQueue: Promise<any> = Promise.resolve();

    private readonly COOKIE_OPTIONS: CookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 3600000,
        signed: true,
        path: '/',
    }

    private endpoints: Endpoints = {
        token: 'https://auth.connect.ai/auth/realms/AHNJ/protocol/openid-connect/token',
        login: 'https://cke.connect.ai/login',
        poll: 'https://cke.connect.ai/poll',
        getUserPoints: 'https://api.connect.ai/get-user-points',
        getUserActive: 'https://api.connect.ai/check-user-active',
    } as const;

    /**
     * Creates an instance of AuthTokenService
     * @param {AuthConfig} config - Configuration object
     * @param {ILogger} logger - Logger instance
     */
    constructor(
        config: AuthConfig,
        logger?: ILogger
    ) {
        this.validateConfig(config);

        this.config = config;
        this.httpClient = new HttpClient();
        this.logger = logger || console;

    }

    /**
     * Returns the current version of the SDK
     */
    public getVersion(): string {
        return ConnectService.VERSION;
    }

    private validateClientIp(ip: string): boolean {
        // IPv4 and IPv6 validation regex
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$/;  // Added |^::1$ to allow IPv6 localhost

        if (!ip || typeof ip !== 'string') {
            return false;
        }

        // Check if IP matches either IPv4 or IPv6 format
        if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
            return false;
        }

        // Additional IPv4 validation for number ranges
        if (ipv4Regex.test(ip)) {
            return ip.split('.').every(num => {
                const number = parseInt(num, 10);
                return number >= 0 && number <= 255;
            });
        }

        return true;
    }

    /**
     * Initiates login process and saves authentication tokens
     */
    public async loginAndSaveToken(
        clientIp: string,
        callbackUrl: string,
        callbackType: string,
        request: IRequest,
        response: IResponse
    ): Promise<LoginResponse> {
        try {
            if (!this.validateClientIp(clientIp)) {
                throw new AuthTokenError('Invalid client IP address', 'INVALID_IP');
            }

            const postData = this.createLoginPostData(clientIp, callbackUrl, callbackType);
            const loginResponse = await this.httpClient.post<{ token: string; url: string }>(
                this.endpoints.login,
                postData
            );

            if (loginResponse.token) {
                response.setCookie('poll_token', loginResponse.token, {
                    ...this.COOKIE_OPTIONS,
                })
            }

            const pollResponse = await this.pollForLoginStatus(request, response, loginResponse.token);

            return {
                connected: pollResponse === 'complete',
            };
        } catch (error) {
            throw this.handleError('Login failed', error);
        }
    }

    /**
     * Enqueues requests to prevent race conditions during token refresh
     */
    private async enqueueRequest<T>(operation: () => Promise<T>): Promise<T> {
        return this.requestQueue = this.requestQueue.then(async () => {
            try {
                return await operation();
            } catch (error) {
                this.logger.error('Queue operation failed', { error });
                throw error;
            }
        });
    }

    /**
     * Gets a valid token
     */
    public async getValidToken(
        request: IRequest,
        response: IResponse
    ): Promise<string | null> {
        return this.enqueueRequest(async () => {
            try {
                const refreshToken = request.cookies[this.cookieName];

                if (!refreshToken) {
                    this.logger.debug('No refresh token found, skipping');
                    return null;
                }

                const refreshedTokens = await this.withRetry(() => this.refreshToken(refreshToken));
                if (!refreshedTokens) {
                    this.logger.error('Failed to refresh tokens');
                    this.clearTokens(response);
                    return null;
                }

                this.saveTokens(refreshedTokens, response);
                return refreshedTokens.accessToken;

            } catch (error) {
                this.logger.error('Token validation failed', {
                    error: error instanceof Error ? error.message : 'Unknown error'
                });
                this.clearTokens(response);
                return null;
            }
        });
    }

    /**
     * Gets user credits using valid token
     */
    public async getUserCredits(req: IRequest, res: IResponse): Promise<UserCredits> {
        const token = await this.getValidToken(req, res);
        if (!token) {
            return {
                status: 'error',
                credits: 0,
            };
        }

        try {
            return await this.httpClient.get<UserCredits>(
                this.endpoints.getUserPoints,
                {
                    headers: { Authorization: `Bearer ${token}` },
                }
            );
        } catch (error) {
            this.handleError('Failed to get user credits', error);
        }
    }

    /**
     * Checks the current user's status
     * @throws {AuthTokenError} When token validation fails
     * @returns {Promise<UserActive>}
     */
    public async checkUserStatus(req: IRequest, res: IResponse): Promise<UserActive> {
        try {
            const token = await this.getValidToken(req, res);
            if (!token) {
                return {
                    status: 'error',
                    isUserActive: false,
                    code: 0,
                };
            }

            try {
                return await this.httpClient.get<UserActive>(
                    this.endpoints.getUserActive,
                    {
                        headers: { Authorization: `Bearer ${token}` },
                    }
                );
            } catch (error) {
                this.handleError('Failed to get user credits', error);
            }
        } catch (error) {
            this.handleError('Failed to get user status', error);
        }
    }

    /**
     * Polls for login status and saves tokens if successful
     */
    public async pollForLoginStatus(request: IRequest, res: IResponse, pollToken: string | null | undefined): Promise<string> {
        try {
            const token = await this.getValidToken(request, res);
            if (token) {
                const result = await this.checkUserStatus(request, res)
                return result.isUserActive ? 'complete' : 'pending'
            }

            if (!pollToken) {
                pollToken = request.cookies['poll_token'];
            }

            const pollResponse = await this.httpClient.get<PollResponse>(
                this.endpoints.poll,
                {
                    params: { token: pollToken },
                }
            );

            if (pollResponse.status === 'complete' && pollResponse.meta) {
                const tokens: AuthTokens = {
                    accessToken: pollResponse.meta.access_token,
                    refreshToken: pollResponse.meta.refresh_token,
                    expiresAt: Date.now() + (pollResponse.meta.expires_in * 1000)
                };

                this.saveTokens(tokens, res);
            }

            return pollResponse.status;
        } catch (error) {
            this.handleError('Poll status check failed', error);
        }
    }

    /**
     * Refreshes the access token using refresh token
     */
    public async refreshToken(refreshToken: string): Promise<AuthTokens> {
        if (!refreshToken || typeof refreshToken !== 'string') {
            throw new AuthTokenError('Invalid refresh token', 'INVALID_REFRESH_TOKEN');
        }

        try {
            const response = await this.httpClient.post<TokenData>(
                this.endpoints.token,
                {
                    refresh_token: refreshToken,
                    client_id: this.config.clientId
                }
            );

            if (!response?.access_token || !response?.refresh_token || !response?.expires_in) {
                throw new AuthTokenError(
                    'Invalid token response',
                    'INVALID_TOKEN_RESPONSE'
                );
            }

            return {
                accessToken: response.access_token,
                refreshToken: response.refresh_token,
                expiresAt: Date.now() + (response.expires_in * 1000)
            };
        } catch (error) {
            if (error instanceof AuthTokenError) {
                throw error;
            }
            throw new AuthTokenError(
                'Failed to refresh token',
                'REFRESH_TOKEN_FAILED',
                error instanceof Error ? error.message : undefined,
                error instanceof Error ? error : undefined,
                error instanceof AuthTokenError ? error.statusCode : undefined
            );
        }
    }

    /**
     * Saves tokens to encrypted cookies
     * @throws {AuthTokenError} If token encryption or cookie setting fails
     */
    private saveTokens(tokens: AuthTokens, response: IResponse): void {
        try {
            response.setCookie(this.cookieName, tokens.refreshToken, {
                ...this.COOKIE_OPTIONS,
                maxAge: Math.min(this.COOKIE_OPTIONS.maxAge, tokens.expiresAt - Date.now())
            });

            this.logger.debug('Tokens saved to cookies', {expiresAt: tokens.expiresAt});
        } catch (error) {
            this.logger.error('Failed to save tokens', { error });
            throw this.handleError('Token save operation failed', error);
        }
    }

    /**
     * Clears authentication tokens
     */
    private clearTokens(response: IResponse): void {
        response.setCookie(this.cookieName, '', {
            ...this.COOKIE_OPTIONS,
            maxAge: 0
        });

        this.logger.debug('Tokens cleared from cookies');
    }

    /**
     * Validates configuration
     */
    private validateConfig(config: AuthConfig): void {
        if (!config.clientId) {
            throw new AuthTokenError(
                'Missing required configuration parameter',
                'INVALID_CONFIG'
            );
        }
    }

    /**
     * Creates login post data
     */
    private createLoginPostData(clientIp: string, callbackUrl?: string, callbackType?: string) {
        const postData: Record<string, string> = {
            client_id: this.config.clientId,
            client_ip: clientIp,
        };

        if (callbackUrl) postData.callback_url = callbackUrl;
        if (callbackType) postData.callback_type = callbackType;

        return postData;
    }

    /**
     * Handles errors consistently
     */
    private handleError(context: string, error: unknown): never {
        // Only log if logger exists
        if (this.logger) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            this.logger.error(context, { message: errorMessage });
        }

        throw new AuthTokenError(
            `${context}: ${error instanceof Error ? error.message : 'Unknown error'}`,
            'OPERATION_FAILED'
        );
    }

    private async withRetry<T>(operation: () => Promise<T>, retries = 3): Promise<T> {
        for (let i = 0; i < retries; i++) {
            try {
                return await operation();
            } catch (error) {
                if (i === retries - 1) throw error;
                await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
            }
        }
        throw new Error('Operation failed after all retries');
    }
}
