import axios, {AxiosInstance, AxiosRequestConfig} from "axios";
import {AuthTokenError} from "../exceptions/AuthTokenError";

export class HttpClient {
    private readonly axios: AxiosInstance;

    constructor(config?: AxiosRequestConfig) {
        this.axios = axios.create({
            timeout: 10000,
            ...config,
        });
    }

    public async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
        try {
            const response = await this.axios.get<T>(url, config);
            return response.data;
        } catch (error) {
            this.handleAxiosError(error);
        }
    }

    public async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
        try {
            const response = await this.axios.post<T>(url, data, config);
            return response.data;
        } catch (error) {
            this.handleAxiosError(error);
        }
    }

    private handleAxiosError(error: unknown): never {
        if (axios.isAxiosError(error)) {
            throw new AuthTokenError(
                'HTTP request failed',
                'HTTP_ERROR',
                error.response?.data?.message || error.message,
                error,
                error.response?.status
            );
        }
        throw new AuthTokenError(
            'Unknown error occurred',
            'UNKNOWN_ERROR',
            error instanceof Error ? error.message : undefined,
            error instanceof Error ? error : undefined
        );
    }

}