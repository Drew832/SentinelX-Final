import { useEffect, useState } from "react";
import {
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { complianceApi } from "@/api/endpoints";

export default function CompliancePage() {
  const [data, setData] = useState<Awaited<ReturnType<typeof complianceApi.radar>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [onlyKev, setOnlyKev] = useState(false);
  const [severity, setSeverity] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    complianceApi
      .radar({ only_kev: onlyKev, severity: severity || undefined })
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [onlyKev, severity]);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="page-heading">Compliance & Audit Radar</h1>
        <div className="page-underline" />
        <p className="page-subtitle">
          A snapshot of how today's CVEs land across the five NIST CSF functions.
          The score on each axis is your posture in that area — higher is healthier.
        </p>
      </div>

      <div className="panel-pad">
        <div className="grid gap-3 md:grid-cols-4">
          <div>
            <label className="label">Severity</label>
            <select
              className="input"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
          <div className="flex items-end">
            <label className="flex items-center gap-2 text-sm text-sentinel-ink">
              <input
                type="checkbox"
                checked={onlyKev}
                onChange={(e) => setOnlyKev(e.target.checked)}
              />
              CISA KEV only
            </label>
          </div>
        </div>
      </div>

      {loading && <div className="panel-pad text-slate-500">Computing radar…</div>}

      {data && (
        <div className="grid gap-5 lg:grid-cols-[1fr_1fr]">
          <div className="analytics-card">
            <h3>NIST CSF Posture</h3>
            <div className="mt-2 flex items-baseline gap-3">
              <div className="text-4xl font-black text-sentinel-gold">
                {data.overall_score.toFixed(1)}
              </div>
              <div className="text-sm text-slate-300">
                / 100 · {data.total_cves.toLocaleString()} CVEs evaluated
              </div>
            </div>
            <div className="mt-4">
              <ResponsiveContainer width="100%" height={320}>
                <RadarChart
                  data={data.per_function.map((f) => ({ subject: f.function, score: f.score }))}
                >
                  <PolarGrid stroke="rgba(255,255,255,0.15)" />
                  <PolarAngleAxis
                    dataKey="subject"
                    tick={{ fill: "#e2e8f0", fontSize: 12 }}
                  />
                  <PolarRadiusAxis
                    domain={[0, 100]}
                    tick={{ fill: "#94a3b8", fontSize: 10 }}
                    stroke="rgba(255,255,255,0.15)"
                  />
                  <Radar
                    dataKey="score"
                    stroke="#e0a82e"
                    fill="#e0a82e"
                    fillOpacity={0.4}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#0f1d3a",
                      border: "1px solid rgba(255,255,255,0.12)",
                      borderRadius: 8,
                      color: "#fff",
                    }}
                  />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="space-y-3">
            {data.per_function.map((f) => (
              <div key={f.function} className="panel p-4">
                <div className="flex items-baseline justify-between gap-3">
                  <div>
                    <div className="text-xs font-bold uppercase tracking-widest text-slate-500">
                      {f.function}
                    </div>
                    <div className="text-2xl font-black text-sentinel-navyDark">
                      {f.score.toFixed(1)}
                      <span className="ml-1 text-xs font-semibold text-slate-400">/100</span>
                    </div>
                  </div>
                  <div className="text-right text-xs text-slate-500">
                    <div>{f.cve_count} CVEs</div>
                    <div>
                      {f.critical} Critical · {f.high} High
                    </div>
                    <div>{f.exploited} Exploited</div>
                  </div>
                </div>
                {f.sample_cves.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {f.sample_cves.map((c) => (
                      <span
                        key={c.cve_id}
                        className="rounded-full border border-sentinel-border bg-sentinel-subtle px-2 py-0.5 font-mono text-[11px] text-slate-600"
                      >
                        {c.cve_id}
                        {c.is_kev ? " ⚡" : ""}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
