export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface CVE {
  cve_id: string;
  description?: string | null;
  published_date?: string | null;
  last_modified_date?: string | null;
  cvss_v3_score?: number | null;
  cvss_v3_severity?: Severity | null;
  cvss_v3_vector?: string | null;
  cvss_v2_score?: number | null;
  cvss_v2_severity?: string | null;
  cvss_v2_vector?: string | null;
  cwe_ids?: string[] | null;
  cpe_products?: Array<{
    criteria?: string;
    vulnerable?: boolean;
    vendor?: string | null;
    product?: string | null;
    version?: string | null;
  }> | null;
  vendors?: string[] | null;
  references?: string[] | null;
  is_kev: boolean;
  kev_date_added?: string | null;
  kev_vendor_project?: string | null;
  kev_product?: string | null;
  kev_vulnerability_name?: string | null;
  kev_required_action?: string | null;
  kev_due_date?: string | null;
  kev_ransomware_use?: string | null;
  source_identifier?: string | null;
  vuln_status?: string | null;
}

export interface CVEListResponse {
  total: number;
  page: number;
  page_size: number;
  items: CVE[];
}

export interface SeverityBucket {
  severity: Severity | string;
  count: number;
}

export interface VendorBucket {
  vendor: string;
  count: number;
}

export interface TrendPoint {
  date: string;
  count: number;
}

export interface StatsResponse {
  total_cves: number;
  kev_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  unscored_count: number;
  categorized_total: number;
  severity_distribution: SeverityBucket[];
  top_vendors: VendorBucket[];
  trend_14d: TrendPoint[];
  trend_window_days: number;
  last_ingest?: string | null;
}

export interface TelemetryPoint {
  cve_id: string;
  cvss_v3_score?: number | null;
  cvss_v3_severity?: Severity | null;
  is_kev: boolean;
  kev_vulnerability_name?: string | null;
  ip_obfuscated: string;
  latitude: number;
  longitude: number;
  country?: string | null;
  city?: string | null;
  org?: string | null;
}

export interface TelemetryResponse {
  generated_at: string;
  cached: boolean;
  source?: string;
  note?: string | null;
  points: TelemetryPoint[];
}

export type UserRole = "admin" | "user" | "guest";

export interface AppUser {
  id: number;
  email: string;
  username: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface AuthToken {
  access_token: string;
  token_type: string;
  user: AppUser;
}

export interface RegisterPending {
  status: "pending_verification";
  email: string;
  detail: string;
}

export interface ProfilePolicyAiResponse {
  profile_id: number;
  cve_id: string;
  policy_type: string;
  recommendation: string;
  justification: string;
  model_used: string;
}

export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

export interface ChatStructuredCve {
  cve_id: string;
  description?: string | null;
  cvss_v3_score?: number | null;
  cvss_v3_severity?: string | null;
  is_kev?: boolean;
  kev_vulnerability_name?: string | null;
  vendors?: string[];
  cwe_ids?: string[];
  published_date?: string | null;
}

export interface ChatStructured {
  intent?: string;
  ids?: string[];
  severity?: string;
  vendor?: string;
  total?: number;
  only_kev?: boolean;
  cves?: ChatStructuredCve[];
  profile?: {
    id: number;
    name: string;
    asset_name?: string | null;
    environment?: string;
    internet_exposed?: boolean;
    business_criticality?: number;
    risk_score?: number;
    risk_label?: string;
    matched_count?: number;
  } | null;
}

export interface ChatResponse {
  answer: string;
  referenced_cves: string[];
  intent?: string | null;
  structured?: ChatStructured | null;
}

export interface NewsArticle {
  id: string;
  title: string;
  url: string;
  source: string;
  category: string;
  description?: string | null;
  image_url?: string | null;
  published_at: string;
  fetched_at: string;
}

export interface NewsListResponse {
  total: number;
  categories: string[];
  counts_by_category: Record<string, number>;
  items: NewsArticle[];
  last_refresh?: string | null;
}

export interface TechStackEntry {
  vendor: string;
  product?: string | null;
  version?: string | null;
}

export type Environment = "PROD" | "DEV" | "TEST";

export interface OrgProfile {
  id: number;
  name: string;
  description?: string | null;
  tech_stack: TechStackEntry[];
  asset_name?: string | null;
  environment: Environment;
  internet_exposed: boolean;
  business_criticality: number;
  risk_score: number;
  risk_label: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  matched_count: number;
  last_scored_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface PrioritizedCVE extends CVE {
  priority_score: number;
  exploit_weight: number;
  is_exploited: boolean;
}

export interface ProfileCvesResponse {
  profile: OrgProfile;
  matched_cves: PrioritizedCVE[];
  total_matches: number;
}

export interface ExecutiveReport {
  summary: {
    profile_id: number;
    profile_name: string;
    asset_name: string | null;
    environment: Environment;
    internet_exposed: boolean;
    business_criticality: number;
    start_date: string;
    end_date: string;
    generated_at: string;
    total_cves: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    exploited_count: number;
    ai_model_used?: string;
  };
  results_brief?: string;
  brief?: string;
  recommendations?: string[];
  key_observations: string[];
  severity_breakdown: Record<string, number>;
  activity: { date: string; count: number }[];
  exposure: {
    exploited: number;
    non_exploited: number;
    internet_exposed_asset: boolean;
  };
  top_cves: Array<{
    cve_id: string;
    cvss_v3_score: number | null;
    cvss_v3_severity: string | null;
    is_exploited: boolean;
    priority_score: number;
    description: string;
    vendors: string[];
    published_date: string | null;
  }>;
  top_vendors: { vendor: string; count: number }[];
}
