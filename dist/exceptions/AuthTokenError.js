"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthTokenError = void 0;
class AuthTokenError extends Error {
    constructor(message, code, errorMessage, originalError, statusCode) {
        super(message);
        this.code = code;
        this.errorMessage = errorMessage;
        this.originalError = originalError;
        this.statusCode = statusCode;
        this.name = 'AuthTokenError';
        // Maintains proper stack trace for where error was thrown
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, AuthTokenError);
        }
        Object.setPrototypeOf(this, AuthTokenError.prototype);
    }
    toJSON() {
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
exports.AuthTokenError = AuthTokenError;
