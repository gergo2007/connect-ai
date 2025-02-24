export declare class AuthTokenError extends Error {
    readonly code: string;
    readonly errorMessage?: string | undefined;
    readonly originalError?: Error | undefined;
    readonly statusCode?: number | string | undefined;
    constructor(message: string, code: string, errorMessage?: string | undefined, originalError?: Error | undefined, statusCode?: number | string | undefined);
    toJSON(): Record<string, unknown>;
}
