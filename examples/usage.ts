import { ConnectService } from '../src';
import { IRequest, IResponse } from '../src/types';

async function example(req: IRequest, res: IResponse) {
    const authService = new ConnectService({
        clientId: 'your-client-id',
    });

    try {
        // Get refresh token from cookies
        const refreshToken = req.cookies?.[ConnectService.COOKIE_NAME] || null;

        // Login and save token
        const loginResult = await authService.loginAndSaveToken(
            '127.0.0.1',
            'https://your-app.com/callback',
            'local_browser',
            res,
            refreshToken,
        );
        console.log('Login result:', loginResult);

        // Check if user is connected
        if (loginResult.connected) {
            // Get user credits
            const credits = await authService.getUserCredits(refreshToken, res);
            console.log('User credits:', credits);

            // Check user status
            const status = await authService.checkUserStatus(refreshToken, res);
            console.log('User status:', status.isUserActive);
        } else {
            console.log('User not connected yet. Please complete the authentication flow.');
        }
    } catch (error) {
        if (error instanceof Error) {
            console.error('Error:', error.message);
        } else {
            console.error('Unknown error occurred');
        }
    }
}

// Example usage with Express.js
/*
import express from 'express';
import cookieParser from 'cookie-parser';

const app = express();
app.use(cookieParser('your-cookie-secret')); // Use the same secret as in your ConnectService config

app.get('/auth', (req, res) => {
    example(req, res);
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
*/

// Example usage with Next.js API route
/*
// pages/api/auth.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { ConnectService } from '../src';
import { serialize } from 'cookie';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    // Implement IResponse interface for Next.js
    const responseAdapter = {
        setCookie: (name: string, value: string, options: any) => {
            res.setHeader('Set-Cookie', serialize(name, value, options));
        }
    };

    const authService = new ConnectService({
        clientId: 'your-client-id',
    });

    try {
        const refreshToken = req.cookies[ConnectService.COOKIE_NAME] || null;
        const pollToken = req.cookies[ConnectService.POLL_COOKIE_NAME] || null;

        const loginResult = await authService.loginAndSaveToken(
            req.headers['x-real-ip']?.toString() || '127.0.0.1',
            `${process.env.NEXT_PUBLIC_URL}/auth/callback`,
            'local_browser',
            responseAdapter,
            refreshToken,
            pollToken
        );

        res.status(200).json({ success: true, connected: loginResult.connected });
    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
    }
}
*/

// Example usage with Fastify
/*
import fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';

const app = fastify();
app.register(fastifyCookie, {
    secret: 'your-cookie-secret'
});

app.get('/auth', async (request, reply) => {
    // Implement IResponse interface for Fastify
    const responseAdapter = {
        setCookie: (name: string, value: string, options: any) => {
            reply.setCookie(name, value, options);
        }
    };

    const authService = new ConnectService({
        clientId: 'your-client-id',
    });

    try {
        const refreshToken = request.cookies[ConnectService.COOKIE_NAME] || null;
        const pollToken = request.cookies[ConnectService.POLL_COOKIE_NAME] || null;

        const loginResult = await authService.loginAndSaveToken(
            request.ip,
            'https://your-app.com/callback',
            'local_browser',
            responseAdapter,
            refreshToken,
            pollToken
        );

        return { success: true, connected: loginResult.connected };
    } catch (error) {
        reply.code(500);
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
});

app.listen({ port: 3000 });
*/
