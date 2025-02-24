export class AuthTokenError extends Error {
    constructor(
        message: string,
        public readonly code: string,
        public readonly errorMessage?: string,
        public readonly originalError?: Error,
        public readonly statusCode?: number | string
    ) {
        super(message);
        this.name = 'AuthTokenError';

        // Maintains proper stack trace for where error was thrown
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, AuthTokenError);
        }

        Object.setPrototypeOf(this, AuthTokenError.prototype);
    }

    public toJSON(): Record<string, unknown> {
        return {
            name: this.name,
            message: this.message,
            code: this.code,
            errorMessage: this.errorMessage,
            statusCode: this.statusCode,
            stack: this.stack,
            originalError: this.originalError ? {
                message: this.originalError.message,
                stack: this.originalError.stack
            } : undefined
        };
    }
}
