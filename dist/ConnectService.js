"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectService = void 0;
const HttpClient_1 = require("./utils/HttpClient");
const AuthTokenError_1 = require("./exceptions/AuthTokenError");
/**
 * Service for handling authentication tokens and user credentials
 * @class ConnectService
 */
class ConnectService {
    /**
     * Creates an instance of AuthTokenService
     * @param {AuthConfig} config - Configuration object
     * @param {ILogger} logger - Logger instance
     */
    constructor(config, logger) {
        this.requestQueue = Promise.resolve();
        this.COOKIE_OPTIONS = {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            maxAge: 3600000,
            signed: true,
            path: '/',
        };
        this.endpoints = {
            token: 'https://auth.connect.ai/auth/realms/AHNJ/protocol/openid-connect/token',
            login: 'https://cke.connect.ai/login',
            poll: 'https://cke.connect.ai/poll',
            getUserPoints: 'https://api.connect.ai/get-user-points',
            getUserActive: 'https://api.connect.ai/check-user-active',
        };
        this.validateConfig(config);
        this.config = config;
        this.httpClient = new HttpClient_1.HttpClient();
        this.logger = logger || console;
    }
    /**
     * Returns the current version of the SDK
     */
    getVersion() {
        return ConnectService.VERSION;
    }
    validateClientIp(ip) {
        // IPv4 and IPv6 validation regex
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$/; // Added |^::1$ to allow IPv6 localhost
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
    async loginAndSaveToken(clientIp, callbackUrl, callbackType, response, refreshToken) {
        try {
            if (!this.validateClientIp(clientIp)) {
                throw new AuthTokenError_1.AuthTokenError('Invalid client IP address', 'INVALID_IP');
            }
            const postData = this.createLoginPostData(clientIp, callbackUrl, callbackType);
            const loginResponse = await this.httpClient.post(this.endpoints.login, postData);
            if (loginResponse.token) {
                response.setCookie(ConnectService.POLL_COOKIE_NAME, loginResponse.token, {
                    ...this.COOKIE_OPTIONS,
                });
            }
            const pollResponse = await this.pollForLoginStatus(loginResponse.token, refreshToken, response);
            return {
                connected: pollResponse.status === 'complete',
            };
        }
        catch (error) {
            throw this.handleError('Login failed', error);
        }
    }
    /**
     * Enqueues requests to prevent race conditions during token refresh
     */
    async enqueueRequest(operation) {
        return this.requestQueue = this.requestQueue.then(async () => {
            try {
                return await operation();
            }
            catch (error) {
                this.logger.error('Queue operation failed', { error });
                throw error;
            }
        });
    }
    /**
     * Gets a valid token
     */
    async getValidToken(refreshToken, response) {
        return this.enqueueRequest(async () => {
            try {
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
            }
            catch (error) {
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
    async getUserCredits(refreshToken, res) {
        const token = await this.getValidToken(refreshToken, res);
        if (!token) {
            return {
                status: 'error',
                credits: 0,
            };
        }
        try {
            return await this.httpClient.get(this.endpoints.getUserPoints, {
                headers: { Authorization: `Bearer ${token}` },
            });
        }
        catch (error) {
            this.handleError('Failed to get user credits', error);
        }
    }
    /**
     * Checks the current user's status
     * @throws {AuthTokenError} When token validation fails
     * @returns {Promise<UserActive>}
     */
    async checkUserStatus(refreshToken, res) {
        try {
            const token = await this.getValidToken(refreshToken, res);
            if (!token) {
                return {
                    status: 'error',
                    isUserActive: false,
                    code: 0,
                };
            }
            try {
                return await this.httpClient.get(this.endpoints.getUserActive, {
                    headers: { Authorization: `Bearer ${token}` },
                });
            }
            catch (error) {
                this.handleError('Failed to get user credits', error);
            }
        }
        catch (error) {
            this.handleError('Failed to get user status', error);
        }
    }
    /**
     * Polls for login status and saves tokens if successful
     */
    async pollForLoginStatus(pollToken, refreshToken, res) {
        try {
            const token = await this.getValidToken(refreshToken, res);
            if (token) {
                const result = await this.checkUserStatus(refreshToken, res);
                return {
                    status: result.isUserActive ? 'complete' : 'pending'
                };
            }
            const pollResponse = await this.httpClient.get(this.endpoints.poll, {
                params: { token: pollToken },
            });
            if (pollResponse.status === 'complete' && pollResponse.meta) {
                const tokens = {
                    accessToken: pollResponse.meta.access_token,
                    refreshToken: pollResponse.meta.refresh_token,
                    expiresAt: Date.now() + (pollResponse.meta.expires_in * 1000)
                };
                this.saveTokens(tokens, res);
            }
            return {
                status: pollResponse.status,
            };
        }
        catch (error) {
            this.handleError('Poll status check failed', error);
        }
    }
    /**
     * Refreshes the access token using refresh token
     */
    async refreshToken(refreshToken) {
        if (!refreshToken || typeof refreshToken !== 'string') {
            throw new AuthTokenError_1.AuthTokenError('Invalid refresh token', 'INVALID_REFRESH_TOKEN');
        }
        try {
            const response = await this.httpClient.post(this.endpoints.token, {
                refresh_token: refreshToken,
                client_id: this.config.clientId
            });
            if (!response?.access_token || !response?.refresh_token || !response?.expires_in) {
                throw new AuthTokenError_1.AuthTokenError('Invalid token response', 'INVALID_TOKEN_RESPONSE');
            }
            return {
                accessToken: response.access_token,
                refreshToken: response.refresh_token,
                expiresAt: Date.now() + (response.expires_in * 1000)
            };
        }
        catch (error) {
            if (error instanceof AuthTokenError_1.AuthTokenError) {
                throw error;
            }
            throw new AuthTokenError_1.AuthTokenError('Failed to refresh token', 'REFRESH_TOKEN_FAILED', error instanceof Error ? error.message : undefined, error instanceof Error ? error : undefined, error instanceof AuthTokenError_1.AuthTokenError ? error.statusCode : undefined);
        }
    }
    /**
     * Saves tokens to encrypted cookies
     * @throws {AuthTokenError} If token encryption or cookie setting fails
     */
    saveTokens(tokens, response) {
        try {
            response.setCookie(ConnectService.COOKIE_NAME, tokens.refreshToken, {
                ...this.COOKIE_OPTIONS,
                maxAge: Math.min(this.COOKIE_OPTIONS.maxAge, tokens.expiresAt - Date.now())
            });
            this.logger.debug('Tokens saved to cookies', { expiresAt: tokens.expiresAt });
        }
        catch (error) {
            this.logger.error('Failed to save tokens', { error });
            throw this.handleError('Token save operation failed', error);
        }
    }
    /**
     * Clears authentication tokens
     */
    clearTokens(response) {
        response.setCookie(ConnectService.COOKIE_NAME, '', {
            ...this.COOKIE_OPTIONS,
            maxAge: 0
        });
        this.logger.debug('Tokens cleared from cookies');
    }
    /**
     * Validates configuration
     */
    validateConfig(config) {
        if (!config.clientId) {
            throw new AuthTokenError_1.AuthTokenError('Missing required configuration parameter', 'INVALID_CONFIG');
        }
    }
    /**
     * Creates login post data
     */
    createLoginPostData(clientIp, callbackUrl, callbackType) {
        console.log(this.config.clientId);
        const postData = {
            client_id: this.config.clientId,
            client_ip: clientIp,
        };
        if (callbackUrl)
            postData.callback_url = callbackUrl;
        if (callbackType)
            postData.callback_type = callbackType;
        return postData;
    }
    /**
     * Handles errors consistently
     */
    handleError(context, error) {
        // Only log if logger exists
        if (this.logger) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            this.logger.error(context, { message: errorMessage });
        }
        throw new AuthTokenError_1.AuthTokenError(`${context}: ${error instanceof Error ? error.message : 'Unknown error'}`, 'OPERATION_FAILED');
    }
    async withRetry(operation, retries = 3) {
        for (let i = 0; i < retries; i++) {
            try {
                return await operation();
            }
            catch (error) {
                if (i === retries - 1)
                    throw error;
                await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
            }
        }
        throw new Error('Operation failed after all retries');
    }
}
exports.ConnectService = ConnectService;
ConnectService.COOKIE_NAME = 'connect.se';
ConnectService.POLL_COOKIE_NAME = 'poll_token';
ConnectService.VERSION = '1.0.0';
