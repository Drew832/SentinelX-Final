import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { profileApi, reportsApi } from "@/api/endpoints";
import type { ExecutiveReport, OrgProfile } from "@/types";
import { SEVERITY_COLORS, formatDate } from "@/utils/format";
import { generateSentinelXReport } from "@/utils/generateReport";

function isoDay(d: Date) {
  return d.toISOString().slice(0, 10);
}

/**
 * Reports hub.
 *
 * Only the executive report is exposed — the technical PDF was retired in
 * the v3 cleanup. CSV / Excel exports still hit the backend, but the PDF
 * route now uses the React-rendered, brand-strict jsPDF generator in
 * `utils/generateReport.ts` so the downloadable PDF exactly matches the
 * approved SentinelX template.
 */
export default function ReportsPage() {
  const [params, setParams] = useSearchParams();
  const [profiles, setProfiles] = useState<OrgProfile[]>([]);
  const [profileId, setProfileId] = useState<number | null>(
    params.get("profile_id") ? Number(params.get("profile_id")) : null,
  );
  const [start, setStart] = useState(
    params.get("start_date") || isoDay(new Date(Date.now() - 30 * 86400000)),
  );
  const [end, setEnd] = useState(params.get("end_date") || isoDay(new Date()));
  const [report, setReport] = useState<ExecutiveReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    profileApi
      .list()
      .then((list) => {
        setProfiles(list);
        if (!profileId && list.length) setProfileId(list[0].id);
      })
      .catch((e) =>
        setError(e?.response?.data?.detail || "Failed to load profiles — sign in required."),
      );
  }, []);

  const load = useCallback(async () => {
    if (!profileId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await reportsApi.executive(profileId, start, end);
      setReport(data);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "Report failed");
    } finally {
      setLoading(false);
    }
  }, [profileId, start, end]);

  useEffect(() => {
    load();
  }, [load]);

  const updateUrl = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    Object.entries(patch).forEach(([k, v]) => next.set(k, v));
    setParams(next, { replace: true });
  };

  const [exporting, setExporting] = useState<string | null>(null);

  const downloadServerExport = async (fmt: "xlsx" | "csv") => {
    if (!profileId) return;
    setExporting(fmt);
    try {
      const url = reportsApi.downloadUrl({
        profile_id: profileId,
        start_date: start,
        end_date: end,
        report_type: "executive",
        format: fmt,
      });
      const token = localStorage.getItem("sentinelx_token");
      const resp = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) throw new Error(`Export failed (${resp.status})`);
      const blob = await resp.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = href;
      a.download = `SentinelX_CVE_Report_${end}.${fmt}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(href);
    } catch (e: any) {
      setError(e?.message || "Export failed");
    } finally {
      setExporting(null);
    }
  };

  /**
   * The PDF is generated entirely client-side using the brand-strict
   * jsPDF renderer in `utils/generateReport.ts`. Doing this on the
   * frontend means the generated PDF stays pixel-identical to the
   * mock-up regardless of the backend's reportlab version.
   */
  const downloadBrandedPdf = () => {
    if (!report) return;
    setExporting("pdf");
    try {
      const recs = report.recommendations && report.recommendations.length
        ? report.recommendations
        : report.key_observations;
      generateSentinelXReport({
        brief:
          (report as any).brief ||
          report.results_brief ||
          "No analyst brief was generated for this report window.",
        recommendation: recs.length ? recs : ["No outstanding recommendations."],
        severity: {
          low: report.summary.low_count || 0,
          medium: report.summary.medium_count || 0,
          high: report.summary.high_count || 0,
          critical: report.summary.critical_count || 0,
        },
        meta: {
          organisation: report.summary.profile_name,
          asset: report.summary.asset_name || undefined,
          startDate: report.summary.start_date,
          endDate: report.summary.end_date,
          generatedAt: report.summary.generated_at,
        },
        filename: `SentinelX_Intelligence_Report_${end}.pdf`,
      });
    } catch (e: any) {
      setError(e?.message || "PDF generation failed");
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-heading">Reports</h1>
          <div className="page-underline" />
          <p className="page-subtitle">
            Pick a profile and a date range — SentinelX builds an executive briefing
            you can hand to leadership in PDF, Excel, or CSV.
          </p>
        </div>
      </div>

      <div className="panel-pad space-y-4">
        <div className="grid gap-3 md:grid-cols-[2fr_1fr_1fr]">
          <div>
            <label className="label">Profile</label>
            <select
              className="input"
              value={profileId ?? ""}
              onChange={(e) => {
                const id = Number(e.target.value);
                setProfileId(id);
                updateUrl({ profile_id: String(id) });
              }}
            >
              <option value="">— select —</option>
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} · {p.environment} · criticality {p.business_criticality}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Start</label>
            <input
              type="date"
              className="input min-w-[160px]"
              value={start}
              onChange={(e) => {
                setStart(e.target.value);
                updateUrl({ start_date: e.target.value });
              }}
            />
          </div>
          <div>
            <label className="label">End</label>
            <input
              type="date"
              className="input min-w-[160px]"
              value={end}
              onChange={(e) => {
                setEnd(e.target.value);
                updateUrl({ end_date: e.target.value });
              }}
            />
          </div>
        </div>

        <div className="flex flex-wrap items-end justify-between gap-3 border-t border-sentinel-border pt-4">
          <div>
            <label className="label">Report</label>
            <div className="rounded-lg border border-sentinel-navy bg-sentinel-navy px-4 py-2 text-sm font-semibold uppercase tracking-wider text-white">
              Executive Intelligence Report
            </div>
          </div>
          <div className="flex items-end gap-2">
            <button
              className="btn-secondary"
              onClick={() => downloadServerExport("csv")}
              disabled={!profileId || exporting === "csv"}
            >
              {exporting === "csv" ? "Exporting…" : "CSV"}
            </button>
            <button
              className="btn-secondary"
              onClick={() => downloadServerExport("xlsx")}
              disabled={!profileId || exporting === "xlsx"}
            >
              {exporting === "xlsx" ? "Exporting…" : "Excel"}
            </button>
            <button
              className="btn-gold"
              onClick={downloadBrandedPdf}
              disabled={!profileId || !report || exporting === "pdf"}
            >
              {exporting === "pdf" ? "Generating…" : "Download PDF"}
            </button>
          </div>
        </div>
      </div>

      {error && <div className="panel-pad text-red-500">{error}</div>}
      {loading && <div className="panel-pad text-slate-500">Crunching report…</div>}

      {report && !loading && (
        <>
          <div className="panel-pad">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-xl font-bold text-sentinel-navyDark">
                  {report.summary.profile_name}
                </h2>
                <div className="mt-1 text-xs text-slate-500">
                  Asset {report.summary.asset_name || "—"} · {report.summary.environment} ·
                  Criticality {report.summary.business_criticality}/5 · Internet exposed:{" "}
                  {report.summary.internet_exposed ? "Yes" : "No"}
                </div>
              </div>
              <div className="text-right text-xs text-slate-500">
                Window: {report.summary.start_date} → {report.summary.end_date}
                <br />
                Generated {formatDate(report.summary.generated_at)}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 md:grid-cols-6">
            {[
              { label: "Total", value: report.summary.total_cves },
              { label: "Critical", value: report.summary.critical_count },
              { label: "High", value: report.summary.high_count },
              { label: "Medium", value: report.summary.medium_count },
              { label: "Low", value: report.summary.low_count },
              { label: "Exploited", value: report.summary.exploited_count },
            ].map((c) => (
              <div key={c.label} className="stat-card">
                <div className="stat-card__label">{c.label}</div>
                <div className="stat-card__value">{c.value.toLocaleString()}</div>
              </div>
            ))}
          </div>

          <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
            <div className="analytics-card">
              <h3>Key Observations</h3>
              <ul className="mt-3 space-y-2 text-sm text-slate-200">
                {report.key_observations.length === 0 ? (
                  <li className="text-slate-400">No observations generated.</li>
                ) : (
                  report.key_observations.map((obs, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="mt-0.5 text-sentinel-gold">•</span>
                      <span>{obs}</span>
                    </li>
                  ))
                )}
              </ul>
            </div>

            <div className="analytics-card">
              <h3>Severity Breakdown</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={Object.entries(report.severity_breakdown).map(([severity, count]) => ({
                      severity,
                      count,
                    }))}
                    dataKey="count"
                    nameKey="severity"
                    innerRadius={50}
                    outerRadius={84}
                    paddingAngle={2}
                  >
                    {Object.keys(report.severity_breakdown).map((sev) => (
                      <Cell key={sev} fill={SEVERITY_COLORS[sev.toUpperCase()] || "#64748b"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#0f1d3a",
                      border: "1px solid rgba(255,255,255,0.12)",
                      borderRadius: 8,
                      color: "#fff",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="analytics-card">
            <h3>Daily Activity</h3>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={report.activity}>
                <defs>
                  <linearGradient id="actFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#e0a82e" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#e0a82e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#9ca3af" tick={{ fontSize: 10 }} />
                <YAxis stroke="#9ca3af" tick={{ fontSize: 10 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "#0f1d3a",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: 8,
                    color: "#fff",
                  }}
                />
                <Area type="monotone" dataKey="count" stroke="#e0a82e" strokeWidth={2} fill="url(#actFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {report.brief && (
            <div className="panel-pad">
              <h3 className="mb-1 text-sm font-semibold uppercase tracking-wider text-sentinel-gold">
                Intelligence Brief
              </h3>
              <div className="h-0.5 w-16 rounded-full bg-sentinel-gold/30 mb-3" />
              <div className="space-y-2 text-sm leading-relaxed text-slate-700">
                {report.brief.split("\n\n").map((para, i) => (
                  <p key={i}>{para}</p>
                ))}
              </div>
            </div>
          )}

          <div className="panel overflow-hidden">
            <div className="border-b border-sentinel-border px-5 py-3 text-sm font-semibold uppercase tracking-wider text-slate-600">
              Top CVEs by Priority
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-sentinel-border text-sm">
                <thead className="bg-sentinel-subtle text-left text-[11px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="px-4 py-2">CVE</th>
                    <th className="px-4 py-2">Severity</th>
                    <th className="px-4 py-2">CVSS</th>
                    <th className="px-4 py-2">Exploited</th>
                    <th className="px-4 py-2">Priority</th>
                    <th className="px-4 py-2">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sentinel-border/70">
                  {report.top_cves.map((c) => (
                    <tr key={c.cve_id} className={c.is_exploited ? "bg-red-50/40" : ""}>
                      <td className="px-4 py-2 font-mono font-semibold text-sentinel-navyDark">
                        {c.cve_id}
                      </td>
                      <td className="px-4 py-2">{c.cvss_v3_severity || "—"}</td>
                      <td className="px-4 py-2">{c.cvss_v3_score?.toFixed(1) ?? "—"}</td>
                      <td className="px-4 py-2">
                        {c.is_exploited ? (
                          <span className="badge-critical">Yes</span>
                        ) : (
                          <span className="text-slate-400">No</span>
                        )}
                      </td>
                      <td className="px-4 py-2 font-semibold">{c.priority_score.toFixed(2)}</td>
                      <td className="px-4 py-2 text-slate-600">{c.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {report.recommendations && report.recommendations.length > 0 && (
            <div className="panel-pad">
              <h3 className="mb-1 text-sm font-semibold uppercase tracking-wider text-sentinel-gold">
                Recommendations
              </h3>
              <div className="h-0.5 w-16 rounded-full bg-sentinel-gold/30 mb-3" />
              <ol className="list-decimal list-inside space-y-2 text-sm text-slate-700">
                {report.recommendations.map((rec, i) => (
                  <li key={i} className="leading-relaxed">{rec}</li>
                ))}
              </ol>
            </div>
          )}
        </>
      )}
    </div>
  );
}
