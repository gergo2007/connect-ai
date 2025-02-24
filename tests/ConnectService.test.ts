import { ConnectService } from '../src/ConnectService';
import { IRequest, IResponse, UserActive } from '../src/types';
import { HttpClient } from '../src/utils/HttpClient';
import { AuthTokenError } from "../src/exceptions/AuthTokenError";

jest.mock('../src/utils/HttpClient');

describe('ConnectService', () => {
    let connectService: ConnectService;
    let mockRequest: IRequest;
    let mockResponse: IResponse;
    let mockHttpClient: jest.SpyInstance;

    beforeEach(() => {
        jest.clearAllMocks();

        connectService = new ConnectService({
            clientId: 'test-client-id'
        });

        mockRequest = {
            cookies: {}
        };

        mockResponse = {
            setCookie: jest.fn(),
        };

        mockHttpClient = jest.spyOn(HttpClient.prototype, 'post');
    });

    describe('Token Management', () => {
        it('should handle token refresh', async () => {
            mockRequest.cookies['connect.se'] = 'test-refresh-token';

            mockHttpClient.mockResolvedValueOnce({
                access_token: 'new-access-token',
                refresh_token: 'new-refresh-token',
                expires_in: 3600
            });

            const token = await connectService.getValidToken(mockRequest, mockResponse);
            expect(token).toBe('new-access-token');
            expect(mockResponse.setCookie).toHaveBeenCalledWith(
                'connect.se',
                'new-refresh-token',
                expect.any(Object)
            );
        });

        it('should return null when no refresh token exists', async () => {
            const token = await connectService.getValidToken(mockRequest, mockResponse);
            expect(token).toBeNull();
        });

        it('should handle refresh token failure', async () => {
            mockRequest.cookies['connect.se'] = 'invalid-refresh-token';

            // Mock HTTP client to reject with an error that includes response data
            mockHttpClient.mockRejectedValueOnce({
                message: 'Request failed with status code 401',
                response: {
                    status: 401,
                    data: {
                        error: 'invalid_grant',
                        error_description: 'Invalid refresh token'
                    }
                }
            });

            const token = await connectService.getValidToken(mockRequest, mockResponse);

            expect(token).toBeNull();
            expect(mockResponse.setCookie).toHaveBeenCalledWith(
                'connect.se',
                '', // Empty string value
                {
                    ...connectService['COOKIE_OPTIONS'],
                    maxAge: 0
                }
            );
        });

    });

    describe('Login Process', () => {
        it('should handle successful login and token saving', async () => {
            // Mock login response
            mockHttpClient
                .mockResolvedValueOnce({
                    connected: true,
                    token: 'test-token',
                    url: 'http://test.com'
                });

            // Mock poll response with get method
            jest.spyOn(HttpClient.prototype, 'get')
                .mockResolvedValueOnce({
                    status: 'complete',
                    meta: {
                        access_token: 'test-access-token',
                        refresh_token: 'test-refresh-token',
                        expires_in: 3600
                    }
                });

            const result = await connectService.loginAndSaveToken(
                '192.168.1.1',
                'https://example.com/cb',
                'oauth',
                mockResponse
            );

            expect(result).toEqual({
                connected: true,
                url: 'http://test.com'
            });
        });

        it('should handle invalid IP address', async () => {
            await expect(
                connectService.loginAndSaveToken(
                    'invalid-ip',
                    'https://example.com/cb',
                    'oauth',
                    mockResponse
                )
            ).rejects.toThrow(AuthTokenError);
        });
    });

    describe('User Status', () => {
        it('should return inactive status when no valid token exists', async () => {
            const result = await connectService.checkUserStatus(mockRequest, mockResponse);
            expect(result).toEqual({
                status: 'error',
                user_active: false,
                code: 0
            });
        });

        it('should return active user status with valid token', async () => {
            mockRequest.cookies['connect.se'] = 'test-refresh-token';

            mockHttpClient.mockResolvedValueOnce({
                access_token: 'new-access-token',
                refresh_token: 'new-refresh-token',
                expires_in: 3600
            });

            const mockUserActive: UserActive = {
                status: 'success',
                user_active: true,
                code: 200
            };

            jest.spyOn(HttpClient.prototype, 'get')
                .mockResolvedValueOnce(mockUserActive);

            const result = await connectService.checkUserStatus(mockRequest, mockResponse);
            expect(result).toEqual(mockUserActive);
        });
    });
});
