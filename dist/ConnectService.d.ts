import { AuthConfig, AuthTokens, ILogger, IRequest, IResponse, LoginResponse, UserActive, UserCredits } from './types';
/**
 * Service for handling authentication tokens and user credentials
 * @class ConnectService
 */
export declare class ConnectService {
    private readonly cookieName;
    private static readonly VERSION;
    private readonly config;
    private readonly httpClient;
    private readonly logger;
    private requestQueue;
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
    loginAndSaveToken(clientIp: string, callbackUrl: string, callbackType: string, request: IRequest, response: IResponse): Promise<LoginResponse>;
    /**
     * Enqueues requests to prevent race conditions during token refresh
     */
    private enqueueRequest;
    /**
     * Gets a valid token
     */
    getValidToken(request: IRequest, response: IResponse): Promise<string | null>;
    /**
     * Gets user credits using valid token
     */
    getUserCredits(req: IRequest, res: IResponse): Promise<UserCredits>;
    /**
     * Checks the current user's status
     * @throws {AuthTokenError} When token validation fails
     * @returns {Promise<UserActive>}
     */
    checkUserStatus(req: IRequest, res: IResponse): Promise<UserActive>;
    /**
     * Polls for login status and saves tokens if successful
     */
    pollForLoginStatus(request: IRequest, res: IResponse, pollToken: string | null | undefined): Promise<string>;
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
