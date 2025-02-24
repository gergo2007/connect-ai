"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Logger = void 0;
class Logger {
    constructor(service) {
        this.service = service;
    }
    error(message, meta) {
        console.error({
            timestamp: new Date().toISOString(),
            level: 'error',
            service: this.service,
            message,
            ...meta
        });
    }
    info(message, meta) {
        console.info({
            timestamp: new Date().toISOString(),
            level: 'info',
            service: this.service,
            message,
            ...meta
        });
    }
    debug(message, meta) {
        console.debug({
            timestamp: new Date().toISOString(),
            level: 'debug',
            service: this.service,
            message,
            ...meta
        });
    }
}
exports.Logger = Logger;
