import axios, { AxiosError } from "axios";
import { extractApiError } from "@/utils/apiError";

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

/**
 * Response interceptor.
 *
 * Two responsibilities:
 *   1. Redirect to the login screen on 401 by calling the registered
 *      callback (set by AuthContext).
 *   2. Attach a render-safe ``displayMessage`` to every rejected error
 *      so any catch-handler that reads ``err.displayMessage`` gets a
 *      single string — even when FastAPI returned a 422 with a list
 *      of Pydantic validation objects (which would otherwise blow up
 *      React with "Objects are not valid as a React child").
 *
 *   Existing call-sites that prefer the explicit ``toErrorMessage(err)``
 *   helper keep working unchanged — both pipelines produce identical
 *   strings.
 */
apiClient.interceptors.response.use(
  (resp) => resp,
  (error: AxiosError & { displayMessage?: string }) => {
    if (error.response?.status === 401 && onUnauthorized) {
      onUnauthorized();
    }
    try {
      error.displayMessage = extractApiError(error);
    } catch {
      error.displayMessage = "Unexpected error";
    }
    return Promise.reject(error);
  },
);
