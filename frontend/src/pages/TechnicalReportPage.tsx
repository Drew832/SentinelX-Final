import { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { reportsApi } from "@/api/endpoints";
import type { ExecutiveReport } from "@/types";
import ReportHeader from "@/components/reports/template/ReportHeader";
import RiskBreakdown from "@/components/reports/template/RiskBreakdown";
import ReportSection from "@/components/reports/template/ReportSection";
import ReportFrame from "@/components/reports/template/ReportFrame";
import { nvdCveUrl } from "@/utils/format";

export default function TechnicalReportPage() {
  const { id } = useParams();
  const [sp] = useSearchParams();
  const profileId = Number(id || sp.get("profile_id") || 0);
  const start = sp.get("start_date") || "";
  const end = sp.get("end_date") || "";
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!profileId) return;
    reportsApi
      .technical(profileId, start, end)
      .then((r) => {
        setData(r);
        setError(null);
      })
      .catch((e: any) => setError(e?.response?.data?.detail || e?.message || "Failed to load report"));
  }, [profileId, start, end]);

  const breakdownCards = useMemo(() => {
    if (!data?.summary) return [];
    const s = data.summary;
    return [
      { label: "Low / Safe", count: s.low_count ?? 0, tone: "low" as const },
      { label: "Medium / Warning", count: s.medium_count ?? 0, tone: "medium" as const },
      { label: "High Risk", count: (s.critical_count ?? 0) + (s.high_count ?? 0), tone: "high" as const },
    ];
  }, [data]);

  if (!profileId) return <div className="panel-pad text-slate-500">Missing profile id.</div>;
  if (error) return <div className="panel-pad text-red-500">{error}</div>;
  if (!data) return <div className="panel-pad text-slate-500">Rendering report…</div>;

  const cves: any[] = data.cves || data.top_cves || [];

  return (
    <ReportFrame
      side={
        <div className="space-y-4">
          <div className="text-xs font-black uppercase tracking-[0.25em] text-slate-900/70">
            Technical Pulse
          </div>
          <div className="rounded-2xl bg-white/20 p-4">
            <div className="text-[11px] font-black uppercase tracking-[0.22em] text-slate-900/70">
              KEV exposure
            </div>
            <div className="mt-1 text-3xl font-black text-slate-950">
              {data.summary?.exploited_count ?? "—"}
            </div>
          </div>
          <div className="rounded-2xl bg-white/20 p-4">
            <div className="text-[11px] font-black uppercase tracking-[0.22em] text-slate-900/70">
              Model
            </div>
            <div className="mt-1 text-xs font-semibold text-slate-950">
              {data.summary?.ai_model_used || "local"}
            </div>
          </div>
          <div className="rounded-2xl bg-white/20 p-4">
            <div className="text-[11px] font-black uppercase tracking-[0.22em] text-slate-900/70">
              Export
            </div>
            <div className="mt-1 text-xs font-semibold text-slate-950">
              Use the Reports dashboard to download PDF/CSV/XLSX.
            </div>
          </div>
        </div>
      }
    >
      <ReportHeader title="Technical" />
      <RiskBreakdown cards={breakdownCards} />

      <ReportSection title="Brief">
        <p className="text-slate-100">{data.brief || "—"}</p>
      </ReportSection>

      <ReportSection title="Technical Findings (clickable CVEs)">
        <div className="space-y-3">
          {cves.slice(0, 30).map((c) => (
            <a
              key={c.cve_id}
              href={nvdCveUrl(c.cve_id)}
              target="_blank"
              rel="noreferrer"
              className="block rounded-2xl border border-white/10 bg-white/5 p-5 hover:bg-white/10"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="font-mono text-base font-semibold text-amber-200">{c.cve_id}</div>
                <div className="text-xs text-slate-200">
                  {(c.cvss_v3_severity || c.severity || "—") + " "}{typeof c.cvss_v3_score === "number" ? c.cvss_v3_score.toFixed(1) : "—"}
                  {c.is_kev ? " · KEV" : ""}
                  {typeof c.epss === "number" ? ` · EPSS ${(c.epss * 100).toFixed(1)}%` : ""}
                </div>
              </div>
              {c.description && <div className="mt-2 text-sm text-slate-100">{c.description}</div>}
              {(c.vendors?.length || 0) > 0 && (
                <div className="mt-2 text-xs text-slate-300">
                  Vendors: {c.vendors.slice(0, 6).join(", ")}
                </div>
              )}
              {(c.references?.length || 0) > 0 && (
                <div className="mt-2 text-xs text-slate-300">
                  References: {c.references.slice(0, 2).join(" · ")}
                </div>
              )}
            </a>
          ))}
        </div>
      </ReportSection>

      <ReportSection title="Recommendations">
        <ul className="mt-3 space-y-2 text-slate-100">
          {(data.recommendations || []).slice(0, 10).map((r: string, i: number) => (
            <li key={i}>• {r}</li>
          ))}
        </ul>
      </ReportSection>
    </ReportFrame>
  );
}

