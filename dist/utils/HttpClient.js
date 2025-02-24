"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HttpClient = void 0;
const axios_1 = __importDefault(require("axios"));
const AuthTokenError_1 = require("../exceptions/AuthTokenError");
class HttpClient {
    constructor(config) {
        this.axios = axios_1.default.create({
            timeout: 10000,
            ...config,
        });
    }
    async get(url, config) {
        try {
            const response = await this.axios.get(url, config);
            return response.data;
        }
        catch (error) {
            this.handleAxiosError(error);
        }
    }
    async post(url, data, config) {
        try {
            const response = await this.axios.post(url, data, config);
            return response.data;
        }
        catch (error) {
            this.handleAxiosError(error);
        }
    }
    handleAxiosError(error) {
        if (axios_1.default.isAxiosError(error)) {
            throw new AuthTokenError_1.AuthTokenError('HTTP request failed', 'HTTP_ERROR', error.response?.data?.message || error.message, error, error.response?.status);
        }
        throw new AuthTokenError_1.AuthTokenError('Unknown error occurred', 'UNKNOWN_ERROR', error instanceof Error ? error.message : undefined, error instanceof Error ? error : undefined);
    }
}
exports.HttpClient = HttpClient;
