export interface AuthConfig {
    clientId: string
}

export interface ILogger {
    error(message: string, meta?: Record<string, unknown>): void
    info(message: string, meta?: Record<string, unknown>): void
    debug(message: string, meta?: Record<string, unknown>): void
}

export interface Endpoints {
    token: string
    login: string
    poll: string
    getUserPoints: string
    getUserActive: string
}

export interface TokenData {
    access_token: string
    refresh_token: string
    expires_in: number
}

export interface LoginResponse {
    connected: boolean,
}

export interface PollResponse {
    status: 'pending' | 'complete' | 'error' | 'invalid'
    token?: string
    meta?: {
        access_token: string
        refresh_token: string
        expires_in: number
    }
}

export interface UserCredits {
    credits: number
    status: string
    isUserActive: boolean
}

export interface UserActive {
    code: number
    status: string
    isUserActive: boolean
}

export interface IRequest {
    cookies: {
        [key: string]: any
    }
}

export interface IResponse {
    setCookie(name: string, value: any, options?: {
        path: "/"
        maxAge: number
        sameSite: 'lax'
        signed: true
        httpOnly: true
        secure: true
    }): void
}

export interface CookieOptions {
    httpOnly: true
    secure: true
    sameSite: 'lax'
    readonly maxAge: 3600000
    signed: true
    path: '/'
}

export interface AuthTokens {
    accessToken: string
    refreshToken: string
    expiresAt: number
}