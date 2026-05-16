import { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { reportsApi } from "@/api/endpoints";
import type { ExecutiveReport } from "@/types";
import ReportHeader from "@/components/reports/template/ReportHeader";
import RiskBreakdown from "@/components/reports/template/RiskBreakdown";
import ReportSection from "@/components/reports/template/ReportSection";
import ReportFrame from "@/components/reports/template/ReportFrame";
import { nvdCveUrl } from "@/utils/format";
import { toErrorMessage } from "@/utils/apiError";

export default function ExecutiveReportPage() {
  const { id } = useParams();
  const [sp] = useSearchParams();
  const profileId = Number(id || sp.get("profile_id") || 0);
  const start = sp.get("start_date") || "";
  const end = sp.get("end_date") || "";
  const [data, setData] = useState<ExecutiveReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!profileId) return;
    reportsApi
      .executive(profileId, start, end)
      .then((r) => {
        setData(r as any);
        setError(null);
      })
      .catch((e: any) => setError(toErrorMessage(e, "Failed to load report")));
  }, [profileId, start, end]);

  const cards = useMemo(() => {
    if (!data) return [];
    return [
      { label: "Low / Safe", count: data.summary.low_count, tone: "low" as const },
      { label: "Medium / Warning", count: data.summary.medium_count, tone: "medium" as const },
      {
        label: "High Risk",
        count: data.summary.critical_count + data.summary.high_count,
        tone: "high" as const,
      },
    ];
  }, [data]);

  if (!profileId) return <div className="panel-pad text-slate-500">Missing profile id.</div>;
  if (error) return <div className="panel-pad text-red-500">{error}</div>;
  if (!data) return <div className="panel-pad text-slate-500">Rendering report…</div>;

  return (
    <ReportFrame
      side={
        <div className="space-y-4">
          <div className="text-xs font-black uppercase tracking-[0.25em] text-slate-900/70">
            Executive Pulse
          </div>
          <div className="rounded-2xl bg-white/20 p-4">
            <div className="text-[11px] font-black uppercase tracking-[0.22em] text-slate-900/70">
              Window
            </div>
            <div className="mt-1 text-sm font-semibold text-slate-950">
              {data.summary.start_date} → {data.summary.end_date}
            </div>
          </div>
          <div className="rounded-2xl bg-white/20 p-4">
            <div className="text-[11px] font-black uppercase tracking-[0.22em] text-slate-900/70">
              KEV exposure
            </div>
            <div className="mt-1 text-3xl font-black text-slate-950">
              {data.summary.exploited_count}
            </div>
          </div>
          <div className="rounded-2xl bg-white/20 p-4">
            <div className="text-[11px] font-black uppercase tracking-[0.22em] text-slate-900/70">
              Model
            </div>
            <div className="mt-1 text-xs font-semibold text-slate-950">
              {(data.summary as any).ai_model_used || "local"}
            </div>
          </div>
        </div>
      }
    >
      <ReportHeader title="Executive" />

      <RiskBreakdown cards={cards} />

      <ReportSection title="Brief">
        <p className="text-slate-100">{(data as any).brief || data.results_brief}</p>
      </ReportSection>

      <ReportSection title="Recommendation">
        <ul className="space-y-2 text-slate-100">
          {((data as any).recommendations || []).slice(0, 10).map((a: string, i: number) => (
            <li key={i}>• {a}</li>
          ))}
        </ul>
      </ReportSection>

      <ReportSection title="Top CVEs (clickable)">
        <div className="grid gap-2">
          {data.top_cves.slice(0, 10).map((c) => (
            <a
              key={c.cve_id}
              href={nvdCveUrl(c.cve_id)}
              target="_blank"
              rel="noreferrer"
              className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-100 hover:bg-white/10"
            >
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono font-semibold text-amber-200">{c.cve_id}</span>
                <span className="text-xs text-slate-300">
                  {c.cvss_v3_severity || "—"}{" "}
                  {typeof c.cvss_v3_score === "number" ? `· ${c.cvss_v3_score.toFixed(1)}` : ""}
                </span>
              </div>
              <div className="mt-1 text-xs text-slate-200">{c.description}</div>
            </a>
          ))}
        </div>
      </ReportSection>
    </ReportFrame>
  );
}

