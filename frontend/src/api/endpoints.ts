import type {
  AuthToken,
  CVE,
  CVEListResponse,
  ChatMessage,
  ChatResponse,
  Environment,
  ExecutiveReport,
  NewsListResponse,
  OrgProfile,
  ProfileCvesResponse,
  ProfilePolicyAiResponse,
  RegisterPending,
  StatsResponse,
  TechStackEntry,
  TelemetryResponse,
} from "@/types";
import { apiClient } from "./client";

export interface CVEListParams {
  page?: number;
  page_size?: number;
  search?: string;
  severity?: string;
  only_kev?: boolean;
  min_score?: number;
  max_score?: number;
  sort?: string;
  published_after?: string;
  published_before?: string;
}

export const authApi = {
  async register(payload: { email: string; username: string; password: string }) {
    const { data } = await apiClient.post<RegisterPending>("/auth/register", payload);
    return data;
  },
  async verifyEmail(payload: { email: string; code: string }) {
    const { data } = await apiClient.post<AuthToken>("/auth/verify-email", payload);
    return data;
  },
  async resendOtp(payload: { email: string }) {
    const { data } = await apiClient.post<RegisterPending>("/auth/resend-otp", payload);
    return data;
  },
  async changePassword(payload: { current_password: string; new_password: string }) {
    const { data } = await apiClient.post<{ status: string }>("/auth/change-password", payload);
    return data;
  },
  async login(username: string, password: string) {
    const form = new URLSearchParams();
    form.append("username", username);
    form.append("password", password);
    const { data } = await apiClient.post<AuthToken>("/auth/login", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    return data;
  },
  async me() {
    const { data } = await apiClient.get("/auth/me");
    return data;
  },
};

export const cveApi = {
  async list(params: CVEListParams = {}) {
    const { data } = await apiClient.get<CVEListResponse>("/cves", { params });
    return data;
  },
  async get(id: string) {
    const { data } = await apiClient.get<CVE>(`/cves/${id}`);
    return data;
  },
  async stats() {
    const { data } = await apiClient.get<StatsResponse>("/cves/stats");
    return data;
  },
  async topPriority(criticality = 5, limit = 5) {
    const { data } = await apiClient.get<
      Array<{
        cve_id: string;
        cvss_v3_score: number | null;
        cvss_v3_severity: string | null;
        is_kev: boolean;
        is_exploited: boolean;
        priority_score: number;
        description: string;
        vendors: string[];
      }>
    >("/cves/top-priority", { params: { limit, criticality } });
    return data;
  },
  exportUrl(params: {
    format?: "csv" | "xlsx";
    severity?: string;
    search?: string;
    vendor?: string;
    start_date?: string;
    end_date?: string;
    only_kev?: boolean;
    min_score?: number;
    max_score?: number;
  } = {}) {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.append(k, String(v));
    });
    const query = qs.toString();
    return `/api/v1/cves/export${query ? "?" + query : ""}`;
  },
};

export const telemetryApi = {
  async fetch() {
    const { data } = await apiClient.get<TelemetryResponse>("/telemetry");
    return data;
  },
};

export const aiApi = {
  async chat(message: string, history: ChatMessage[]) {
    const { data } = await apiClient.post<ChatResponse>("/ai/chat", { message, history });
    return data;
  },
};

export const newsApi = {
  async list(params: { category?: string; search?: string; limit?: number } = {}) {
    const { data } = await apiClient.get<NewsListResponse>("/news", { params });
    return data;
  },
  async refresh() {
    const { data } = await apiClient.post<NewsListResponse>("/news/refresh");
    return data;
  },
};

export interface ProfileUpsertPayload {
  name: string;
  description?: string;
  tech_stack: TechStackEntry[];
  asset_name?: string | null;
  environment?: Environment;
  internet_exposed?: boolean;
  business_criticality?: number;
}

/** LLM-backed recommendation for one CVE within an org profile (see /policy-ai). */
export const policyAiApi = {
  async types() {
    const { data } = await apiClient.get<string[]>("/policy-ai/types");
    return data;
  },
  async recommendForProfile(payload: { profile_id: number; cve_id: string; policy_type: string }) {
    const { data } = await apiClient.post<ProfilePolicyAiResponse>(
      "/policy-ai/recommend",
      payload,
    );
    return data;
  },
};

export const profileApi = {
  async list() {
    const { data } = await apiClient.get<OrgProfile[]>("/profiles");
    return data;
  },
  async create(payload: ProfileUpsertPayload) {
    const { data } = await apiClient.post<OrgProfile>("/profiles", payload);
    return data;
  },
  async update(id: number, payload: Partial<ProfileUpsertPayload>) {
    const { data } = await apiClient.put<OrgProfile>(`/profiles/${id}`, payload);
    return data;
  },
  async remove(id: number) {
    await apiClient.delete(`/profiles/${id}`);
  },
  async rescore(id: number) {
    const { data } = await apiClient.post<OrgProfile>(`/profiles/${id}/rescore`);
    return data;
  },
  async cves(id: number) {
    const { data } = await apiClient.get<ProfileCvesResponse>(`/profiles/${id}/cves`);
    return data;
  },
  exportUrl(id: number) {
    return `/api/v1/profiles/${id}/export`;
  },
};

export const reportsApi = {
  /**
   * Fetch an executive report.
   *
   * When ``includeAi`` is false the backend skips the LLM call and
   * returns the deterministic narrative immediately, which keeps the
   * live preview snappy on slow networks or when the AI provider is
   * unreachable. The actual PDF download always asks for the AI brief.
   */
  async executive(
    profileId: number,
    startDate: string,
    endDate: string,
    opts: { includeAi?: boolean; signal?: AbortSignal } = {},
  ) {
    const { data } = await apiClient.get<ExecutiveReport>("/reports/executive", {
      params: {
        profile_id: profileId,
        start_date: startDate,
        end_date: endDate,
        include_ai: opts.includeAi === undefined ? true : opts.includeAi,
      },
      signal: opts.signal,
      // The AI brief alone can take ~30s; we give the request a slightly
      // larger budget than the global default so the operator never has
      // to deal with a misleading "Network Error" on a working call.
      timeout: 90000,
    });
    return data;
  },
  async technical(
    profileId: number,
    startDate: string,
    endDate: string,
    opts: { includeAi?: boolean } = {},
  ) {
    const { data } = await apiClient.get<{ summary: any; cves: any[] }>("/reports/technical", {
      params: {
        profile_id: profileId,
        start_date: startDate,
        end_date: endDate,
        include_ai: opts.includeAi === undefined ? true : opts.includeAi,
      },
      timeout: 90000,
    });
    return data;
  },
  exportUrl(profileId: number, startDate: string, endDate: string, format: "csv" | "xlsx" | "pdf") {
    const qs = new URLSearchParams({
      profile_id: String(profileId),
      start_date: startDate,
      end_date: endDate,
      format,
    });
    return `/api/v1/reports/executive/export?${qs.toString()}`;
  },
  downloadUrl(params: {
    profile_id: number;
    start_date: string;
    end_date: string;
    report_type: "executive" | "technical";
    format: "csv" | "xlsx" | "pdf";
  }) {
    const qs = new URLSearchParams({
      profile_id: String(params.profile_id),
      start_date: params.start_date,
      end_date: params.end_date,
      report_type: params.report_type,
      format: params.format,
    });
    return `/api/v1/reports/download?${qs.toString()}`;
  },
};

export interface PolicyEvidence {
  cve_id: string;
  matched_terms: string[];
  match_type: "keyword" | "cwe" | "vendor" | "severity" | "kev";
}

export interface PolicyRecommendation {
  policy_name: string;
  reason: string;
  justification: string;
  priority: "HIGH" | "MEDIUM" | "LOW";
  matched_cves: number;
  example_cves: string[];
  matched_terms: string[];
  evidence: PolicyEvidence[];
}

export const policiesApi = {
  async recommend(
    filters: {
      severity?: string;
      only_kev?: boolean;
      search?: string;
      vendor?: string;
      cve_ids?: string[];
      limit?: number;
      /**
       * When true, the backend asks Claude to verify each rule-based
       * recommendation, drop incorrect mappings, and refine the
       * justification text with concrete CVE-level evidence.
       */
      ai_validate?: boolean;
    } = {},
  ) {
    const { data } = await apiClient.post<{
      total_cves_evaluated: number;
      ai_model_used: string;
      recommendations: PolicyRecommendation[];
    }>("/policies/recommend", filters, {
      // Policy generation + AI verification is the heaviest call in
      // the platform; give it a longer ceiling than the default.
      timeout: 90000,
    });
    return data;
  },
};

export const kevApi = {
  async list(params: {
    vendor?: string;
    product?: string;
    search?: string;
    ransomware_only?: boolean;
    page?: number;
    page_size?: number;
  } = {}) {
    const { data } = await apiClient.get("/kev", { params });
    return data as {
      total: number;
      page: number;
      page_size: number;
      items: Array<any>;
      vendors: Array<{ vendor: string; count: number }>;
      banner: { total_kev: number; ransomware_linked: number };
    };
  },
};

export const complianceApi = {
  async radar(params: { only_kev?: boolean; severity?: string; vendor?: string } = {}) {
    const { data } = await apiClient.get("/compliance/radar", { params });
    return data as {
      overall_score: number;
      total_cves: number;
      per_function: Array<{
        function: string;
        score: number;
        risk: number;
        cve_count: number;
        critical: number;
        high: number;
        exploited: number;
        sample_cves: Array<{ cve_id: string; severity: string | null; is_kev: boolean }>;
      }>;
    };
  },
};

export const assetHealthApi = {
  async get(params: { only_kev?: boolean; severity?: string; vendor?: string } = {}) {
    const { data } = await apiClient.get("/assets/health", { params });
    return data as {
      total_cves: number;
      categories_tracked: number;
      categories: Array<{
        category: string;
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        exploited: number;
        weighted_risk: number;
        sample_cves: string[];
      }>;
    };
  },
};

export const geoApi = {
  async fetchForCve(cveId: string, limit = 50) {
    const { data } = await apiClient.get(`/cves/${cveId}/geo`, { params: { limit } });
    return data as {
      cve_id: string;
      source: string;
      note: string | null;
      points: Array<{
        cve_id: string;
        ip_obfuscated: string;
        latitude: number;
        longitude: number;
        country: string | null;
        city: string | null;
        org: string | null;
        severity: string;
        cvss_v3_score: number | null;
        is_kev: boolean;
      }>;
    };
  },
};

export const adminApi = {
  async ingestNvd(minutes = 60) {
    const { data } = await apiClient.post(`/admin/ingest/nvd?minutes=${minutes}`);
    return data;
  },
  async ingestKev() {
    const { data } = await apiClient.post(`/admin/ingest/kev`);
    return data;
  },
};
