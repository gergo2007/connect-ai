import { ConnectService } from '../src';
import { IRequest, IResponse } from '../src/types';

async function example(req: IRequest, res: IResponse) {
    const authService = new ConnectService({
        baseUrl: 'https://api.connect.ai',
        cookieSecret: 'your-secret-key',
        clientId: 'your-client-id', // Add required clientId
    });

    try {
        // Login with required callbackType parameter
        const loginResult = await authService.loginAndSaveToken(
            '127.0.0.1',
            'https://your-app.com/callback',
            'local_browser', // Add callbackType parameter
            res
        );
        console.log('Login result:', loginResult);

        // Get user credits
        const credits = await authService.getUserCredits(req, res);
        console.log('User credits:', credits);

        const status = await authService.checkUserStatus(req, res);
        console.log('User status:', status.user_active);
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
