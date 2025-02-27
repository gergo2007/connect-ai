import { AuthConfig, AuthTokens, ILogger, IResponse, LoginResponse, UserActive, UserCredits } from './types';
/**
 * Service for handling authentication tokens and user credentials
 * @class ConnectService
 */
export declare class ConnectService {
    static readonly COOKIE_NAME = "connect.se";
    static readonly POLL_COOKIE_NAME = "poll_token";
    private static readonly VERSION;
    private readonly config;
    private readonly httpClient;
    private readonly logger;
    private requestQueue;
    private tokenCache;
    private readonly TOKEN_CACHE_BUFFER_MS;
    private readonly COOKIE_OPTIONS;
    private endpoints;
    /**
     * Creates an instance of AuthTokenService
     * @param {AuthConfig} config - Configuration object
     * @param {ILogger} logger - Logger instance
     */
    constructor(config: AuthConfig, logger?: ILogger);
    /**
     * Returns the current version of the SDK
     */
    getVersion(): string;
    private validateClientIp;
    /**
     * Initiates login process and saves authentication tokens
     */
    loginAndSaveToken(clientIp: string, callbackUrl: string, callbackType: string, response: IResponse, refreshToken: string | null, pollToken: string | null): Promise<LoginResponse>;
    private clearPollToken;
    /**
     * Enqueues requests to prevent race conditions during token refresh
     */
    private enqueueRequest;
    /**
     * Gets a valid token
     */
    getValidToken(refreshToken: string | null, response: IResponse): Promise<string | null>;
    private invalidateCache;
    /**
     * Gets user credits using valid token
     */
    getUserCredits(refreshToken: string | null, res: IResponse): Promise<UserCredits>;
    /**
     * Checks the current user's status
     * @throws {AuthTokenError} When token validation fails
     * @returns {Promise<UserActive>}
     */
    checkUserStatus(refreshToken: string | null, res: IResponse): Promise<UserActive>;
    /**
     * Polls for login status and saves tokens if successful
     */
    pollForLoginStatus(pollToken: string, refreshToken: string | null, res: IResponse): Promise<{
        status: string;
    }>;
    /**
     * Refreshes the access token using refresh token
     */
    refreshToken(refreshToken: string): Promise<AuthTokens>;
    /**
     * Saves tokens to encrypted cookies
     * @throws {AuthTokenError} If token encryption or cookie setting fails
     */
    private saveTokens;
    /**
     * Clears authentication tokens
     */
    private clearTokens;
    /**
     * Validates configuration
     */
    private validateConfig;
    /**
     * Creates login post data
     */
    private createLoginPostData;
    /**
     * Handles errors consistently
     */
    private handleError;
    private withRetry;
}
