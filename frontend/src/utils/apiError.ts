/**
 * Normalise any error thrown by axios / fetch / our own code into a
 * single human-readable string that is **always safe to render**.
 *
 * Why this exists
 * ---------------
 * FastAPI returns 4xx errors with two very different shapes:
 *
 *   - Business errors (raised via ``HTTPException(detail="...")``) come
 *     back as ``{"detail": "string"}``.
 *   - Pydantic validation failures (HTTP 422) come back as
 *     ``{"detail": [{"type": ..., "loc": [...], "msg": ..., "input": ...,
 *     "ctx": ...}, ...]}``.
 *
 * Many call sites used to do ``setError(err?.response?.data?.detail)``
 * which works for the first shape but, for the second, sets the *array
 * of objects* into a string state slot. React then tries to render the
 * array as a child node and explodes with:
 *
 *   Objects are not valid as a React child (found: object with keys
 *   {type, loc, msg, input, ctx}). If you meant to render a collection
 *   of children, use an array instead.
 *
 * which is exactly what blew up the live console. ``extractApiError``
 * collapses every error shape we have ever seen from the backend into a
 * single string so the UI stays crash-free no matter what comes back.
 */

interface PydanticIssue {
  type?: string;
  loc?: Array<string | number>;
  msg?: string;
  input?: unknown;
  ctx?: Record<string, unknown>;
  message?: string;
}

function isPydanticIssue(value: unknown): value is PydanticIssue {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return typeof v.msg === "string" || typeof v.message === "string";
}

function formatIssue(issue: PydanticIssue): string {
  const msg = (issue.msg || issue.message || "Invalid value").toString();
  const loc = Array.isArray(issue.loc) ? issue.loc : [];
  // FastAPI prefixes the location with "body" / "query" / "path" — strip
  // that so the user sees "password: too short" rather than
  // "body, password: too short".
  const fieldParts = loc.filter(
    (p, i) => !(i === 0 && typeof p === "string" && ["body", "query", "path", "header", "cookie"].includes(p)),
  );
  const field = fieldParts.length ? fieldParts.join(".") : "";
  return field ? `${field}: ${msg}` : msg;
}

function fromDetail(detail: unknown): string | null {
  if (detail == null) return null;
  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (isPydanticIssue(item) ? formatIssue(item) : safeToString(item)))
      .filter(Boolean);
    if (messages.length === 0) return null;
    if (messages.length === 1) return messages[0];
    return messages.map((m) => `• ${m}`).join("\n");
  }

  if (isPydanticIssue(detail)) return formatIssue(detail);
  if (typeof detail === "object") {
    // Best-effort: surface a "message" field, otherwise stringify safely.
    const obj = detail as Record<string, unknown>;
    if (typeof obj.message === "string") return obj.message;
    if (typeof obj.error === "string") return obj.error;
    return safeToString(obj);
  }
  return safeToString(detail);
}

function safeToString(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export interface ExtractOptions {
  /** Friendly fallback used when nothing else can be derived. */
  fallback?: string;
}

/**
 * Pull the most useful human message out of an error.
 */
export function extractApiError(error: unknown, opts: ExtractOptions = {}): string {
  const fallback = opts.fallback ?? "Something went wrong. Please try again.";

  if (!error) return fallback;
  if (typeof error === "string") return error;

  const err = error as {
    response?: { status?: number; data?: unknown; statusText?: string };
    request?: unknown;
    message?: string;
    code?: string;
    name?: string;
  };

  if (err.response) {
    const data = err.response.data;

    if (typeof data === "string" && data.trim()) {
      const trimmed = data.trim();
      // Reverse-proxy / HTML error pages aren't useful to render verbatim;
      // fall through to the status-code mapping below.
      const looksLikeHtml = trimmed.startsWith("<") || /<\/?html/i.test(trimmed);
      if (!looksLikeHtml && trimmed.length < 400) return trimmed;
    }

    if (data && typeof data === "object") {
      const body = data as Record<string, unknown>;
      const detailMsg = fromDetail(body.detail);
      if (detailMsg) return detailMsg;

      // Some endpoints return `{message: "..."}` or `{error: "..."}`.
      if (typeof body.message === "string") return body.message;
      if (typeof body.error === "string") return body.error;
      if (Array.isArray(body.errors)) {
        const collated = fromDetail(body.errors);
        if (collated) return collated;
      }
    }

    if (err.response.status === 401) return "Your session has expired. Please sign in again.";
    if (err.response.status === 403) return "You don't have permission to perform this action.";
    if (err.response.status === 404) return "The requested resource could not be found.";
    if (err.response.status === 429) return "Too many requests — please slow down and try again.";
    if (err.response.status && err.response.status >= 500) {
      return "The SentinelX backend hit an internal error. Please retry shortly.";
    }
    if (err.response.statusText) return err.response.statusText;
  }

  if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT" || err.name === "AbortError") {
    return "The request timed out. Please retry.";
  }
  if (err.request) {
    return "Cannot reach the SentinelX backend. Check your network and try again.";
  }
  if (typeof err.message === "string" && err.message.trim()) return err.message;

  return fallback;
}

/**
 * Convenience: same as ``extractApiError`` but never throws and always
 * returns a non-empty string. Useful when piping directly into a
 * ``setError`` setter.
 */
export function toErrorMessage(error: unknown, fallback?: string): string {
  return extractApiError(error, { fallback });
}
