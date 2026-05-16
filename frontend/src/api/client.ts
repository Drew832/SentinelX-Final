import axios, { AxiosError } from "axios";

const baseURL = import.meta.env.VITE_API_BASE_URL || "/api/v1";

export const apiClient = axios.create({
  baseURL,
  timeout: 30000,
});

let onUnauthorized: (() => void) | null = null;
export const setOnUnauthorized = (cb: () => void) => {
  onUnauthorized = cb;
};

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("sentinelx_token");
  if (token) {
    config.headers = config.headers ?? {};
    (config.headers as Record<string, string>).Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (resp) => resp,
  (error: AxiosError) => {
    if (error.response?.status === 401 && onUnauthorized) {
      onUnauthorized();
    }
    return Promise.reject(error);
  },
);
