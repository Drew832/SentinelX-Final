export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#facc15",
  LOW: "#10b981",
  UNSCORED: "#94a3b8",
};

export const severityColor = (sev?: string | null, score?: number | null): string => {
  if (sev && SEVERITY_COLORS[sev.toUpperCase()]) return SEVERITY_COLORS[sev.toUpperCase()];
  if (typeof score === "number") {
    if (score >= 9) return SEVERITY_COLORS.CRITICAL;
    if (score >= 7) return SEVERITY_COLORS.HIGH;
    if (score >= 4) return SEVERITY_COLORS.MEDIUM;
    return SEVERITY_COLORS.LOW;
  }
  return "#64748b";
};

export const formatDate = (iso?: string | null): string => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

export const formatDay = (iso?: string | null): string => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString();
  } catch {
    return iso;
  }
};

export const truncate = (s: string | null | undefined, n = 200): string => {
  if (!s) return "";
  return s.length <= n ? s : s.slice(0, n).trim() + "…";
};

export const timeAgo = (iso?: string | null): string => {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diff = Math.floor((Date.now() - then) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
};

/** NIST NVD detail page for a CVE id (e.g. CVE-2024-0001). */
export const nvdCveUrl = (cveId: string): string => {
  const id = (cveId || "").trim().toUpperCase();
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
};

export const riskColor = (label: string): string => {
  switch (label.toUpperCase()) {
    case "CRITICAL":
      return "#ef4444";
    case "HIGH":
      return "#f97316";
    case "MEDIUM":
      return "#facc15";
    case "LOW":
      return "#38bdf8";
    default:
      return "#10b981";
  }
};
