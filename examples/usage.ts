import { ConnectService } from '../src';
import { IRequest, IResponse } from '../src/types';

async function example(req: IRequest, res: IResponse) {
    const authService = new ConnectService({
        clientId: 'your-client-id',
    });

    try {
        const refreshToken = 'token-from-cookie'

        // Login with required callbackType parameter
        const loginResult = await authService.loginAndSaveToken(
            '127.0.0.1',
            'https://your-app.com/callback',
            'local_browser', // Add callbackType parameter,
            res,
            refreshToken,
        );
        console.log('Login result:', loginResult);

        // Get user credits
        const credits = await authService.getUserCredits(loginResult.token, res);
        console.log('User credits:', credits);

        const status = await authService.checkUserStatus(refreshToken, res);
        console.log('User status:', status.isUserActive);
    } catch (error) {
        if (error instanceof Error) {
            console.error('Error:', error.message);
        } else {
            console.error('Unknown error occurred');
        }
    }
}

// Example usage with Express.js
// app.get('/auth', (req, res) => {
//     example(req, res);
// });

// Example usage with other frameworks
// Implement IRequest and IResponse interfaces for your framework
// example(yourFrameworkRequest, yourFrameworkResponse);
