import { ILogger } from "../types";
export declare class Logger implements ILogger {
    private readonly service;
    constructor(service: string);
    error(message: string, meta?: Record<string, unknown>): void;
    info(message: string, meta?: Record<string, unknown>): void;
    debug(message: string, meta?: Record<string, unknown>): void;
}
