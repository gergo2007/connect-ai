import {ILogger} from "../types";

export class Logger implements ILogger {
    constructor(private readonly service: string) {}

    error(message: string, meta?: Record<string, unknown>): void {
        console.error({
            timestamp: new Date().toISOString(),
            level: 'error',
            service: this.service,
            message,
            ...meta
        });
    }

    info(message: string, meta?: Record<string, unknown>): void {
        console.info({
            timestamp: new Date().toISOString(),
            level: 'info',
            service: this.service,
            message,
            ...meta
        });
    }

    debug(message: string, meta?: Record<string, unknown>): void {
        console.debug({
            timestamp: new Date().toISOString(),
            level: 'debug',
            service: this.service,
            message,
            ...meta
        });
    }
}