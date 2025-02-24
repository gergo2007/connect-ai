import { AxiosRequestConfig } from "axios";
export declare class HttpClient {
    private readonly axios;
    constructor(config?: AxiosRequestConfig);
    get<T>(url: string, config?: AxiosRequestConfig): Promise<T>;
    post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T>;
    private handleAxiosError;
}
