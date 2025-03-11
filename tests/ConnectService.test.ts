import { ConnectService } from '../src/ConnectService';
import { IResponse, UserActive } from '../src/types';
import { HttpClient } from '../src/utils/HttpClient';
import { AuthTokenError } from "../src/exceptions/AuthTokenError";

jest.mock('../src/utils/HttpClient');

describe('ConnectService', () => {
    let connectService: ConnectService;
    let mockResponse: IResponse;
    let mockHttpClient: jest.Mocked<HttpClient>;

    beforeEach(() => {
        jest.clearAllMocks();

        connectService = new ConnectService({
            clientId: 'test-client-id'
        });

        mockResponse = {
            setCookie: jest.fn(),
        };

        mockHttpClient = HttpClient.prototype as jest.Mocked<HttpClient>;
    });

    describe('Token Management', () => {
        it('should handle token refresh', async () => {
            const refreshToken = 'test-refresh-token';

            mockHttpClient.post.mockResolvedValueOnce({
                access_token: 'new-access-token',
                refresh_token: 'new-refresh-token',
                expires_in: 3600
            });

            const token = await connectService.getValidToken(refreshToken, mockResponse);
            expect(token).toBe('new-access-token');
            expect(mockResponse.setCookie).toHaveBeenCalledWith(
                'connect.se',
                'new-refresh-token',
                expect.objectContaining({
                    httpOnly: true,
                    secure: true
                })
            );
        });

        it('should return null when no refresh token exists', async () => {
            const token = await connectService.getValidToken(null, mockResponse);
            expect(token).toBeNull();
        });

        it('should handle refresh token failure', async () => {
            const refreshToken = 'invalid-refresh-token';

            // Mock HTTP client to reject with an error
            mockHttpClient.post.mockRejectedValueOnce(new Error('Invalid refresh token'));

            const token = await connectService.getValidToken(refreshToken, mockResponse);

            expect(token).toBeNull();
            expect(mockResponse.setCookie).toHaveBeenCalledWith(
                'connect.se',
                '',
                expect.objectContaining({
                    maxAge: 0
                })
            );
        });
    });

    describe('Login Process', () => {
        it('should handle successful login and token saving', async () => {
            // Mock login response
            mockHttpClient.post.mockResolvedValueOnce({
                token: 'test-poll-token',
                url: 'http://test.com'
            });

            // Mock poll response
            mockHttpClient.get.mockResolvedValueOnce({
                status: 'complete',
                meta: {
                    access_token: 'test-access-token',
                    refresh_token: 'test-refresh-token',
                    expires_in: 3600
                }
            });

            // Mock the getUserActive API call
            mockHttpClient.get.mockResolvedValueOnce({
                detail: {
                    status: 'success',
                    code: '200',
                    description: 'User is active',
                    user_active: true
                }
            });

            const result = await connectService.loginAndSaveToken(
                '192.168.1.1',
                'https://example.com/cb',
                'oauth',
                mockResponse,
                null,
            );

            expect(result).toEqual({
                connected: true
            });

            expect(mockResponse.setCookie).toHaveBeenCalledWith(
                'poll_token',
                'test-poll-token',
                expect.any(Object)
            );
        });

        it('should handle invalid IP address', async () => {
            await expect(
                connectService.loginAndSaveToken(
                    'invalid-ip',
                    'https://example.com/cb',
                    'oauth',
                    mockResponse,
                    null,
                )
            ).rejects.toThrow(AuthTokenError);
        });
    });

    describe('User Status', () => {
        it('should return inactive status when no valid token exists', async () => {
            const result = await connectService.checkUserStatus(null, mockResponse);
            expect(result).toEqual({
                status: 'error',
                isUserActive: false,
                code: 0
            });
        });

        it('should return active user status with valid token', async () => {
            const refreshToken = 'test-refresh-token';

            // Mock the token refresh
            mockHttpClient.post.mockResolvedValueOnce({
                access_token: 'new-access-token',
                refresh_token: 'new-refresh-token',
                expires_in: 3600
            });

            mockHttpClient.get.mockResolvedValueOnce({
                detail: {
                    status: 'success',
                    code: '200',
                    description: 'User is active',
                    user_active: true
                }
            });

            const result = await connectService.checkUserStatus(refreshToken, mockResponse);
            expect(result).toEqual({
                status: 'success',
                isUserActive: true,
                code: 200
            });
        });
    });

    describe('User Credits', () => {
        it('should return error status when no valid token exists', async () => {
            const result = await connectService.getUserCredits(null, mockResponse);
            expect(result).toEqual({
                status: 'error',
                credits: 0
            });
        });

        it('should fetch user credits with valid token', async () => {
            const refreshToken = 'test-refresh-token';

            // Mock the token refresh
            mockHttpClient.post.mockResolvedValueOnce({
                access_token: 'new-access-token',
                refresh_token: 'new-refresh-token',
                expires_in: 3600
            });

            mockHttpClient.get.mockResolvedValueOnce({
                detail: {
                    status: 'success',
                    points_balance: 100
                }
            });

            const result = await connectService.getUserCredits(refreshToken, mockResponse);
            expect(result).toEqual({
                status: 'success',
                credits: 100
            });
        });
    });

    describe('Poll For Login Status', () => {
        it('should handle complete poll status with existing token', async () => {
            const refreshToken = 'test-refresh-token';
            const pollToken = 'test-poll-token';

            // Mock the poll API call to return complete status
            mockHttpClient.get.mockResolvedValueOnce({
                status: 'complete',
                meta: {
                    access_token: 'test-access-token',
                    refresh_token: 'test-refresh-token',
                    expires_in: 3600
                }
            });

            // Mock the getUserActive API call
            mockHttpClient.get.mockResolvedValueOnce({
                detail: {
                    status: 'success',
                    code: '200',
                    description: 'User is active',
                    user_active: true
                }
            });

            const result = await connectService.pollForLoginStatus(pollToken, refreshToken, mockResponse);
            expect(result).toEqual({
                status: 'complete',
                code: 200,
                isUserActive: true,
            });

            // Verify that the refresh token was saved
            expect(mockResponse.setCookie).toHaveBeenCalledWith(
                'connect.se',
                'test-refresh-token',
                expect.any(Object)
            );
        });

        it('should handle pending poll status', async () => {
            const pollToken = 'test-poll-token';

            // Mock the poll API call to return pending status
            mockHttpClient.get.mockResolvedValueOnce({
                status: 'pending'
            });

            const result = await connectService.pollForLoginStatus(pollToken, null, mockResponse);
            expect(result).toEqual({
                status: 'pending',
                code: 200,
                isUserActive: false,
            });
        });
    });
});
