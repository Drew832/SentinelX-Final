import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { assetHealthApi } from "@/api/endpoints";

export default function AssetHealthPage() {
  const [data, setData] = useState<Awaited<ReturnType<typeof assetHealthApi.get>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [onlyKev, setOnlyKev] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    assetHealthApi
      .get({ only_kev: onlyKev })
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [onlyKev]);

  const chartData = data?.categories.map((c) => ({
    category: c.category,
    Critical: c.critical,
    High: c.high,
    Medium: c.medium,
    Low: c.low,
    Exploited: c.exploited,
  })) || [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="page-heading">Asset Health Dashboard</h1>
        <div className="page-underline" />
        <p className="page-subtitle">
          CVEs grouped by the technology category they hit (web servers, databases, OS, …).
          Quickest way to spot which asset class is carrying the biggest patch backlog.
        </p>
      </div>

      <div className="panel-pad flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-sentinel-ink">
          <input
            type="checkbox"
            checked={onlyKev}
            onChange={(e) => setOnlyKev(e.target.checked)}
          />
          CISA KEV only
        </label>
        <span className="ml-auto text-xs text-slate-500">
          {data?.total_cves.toLocaleString() ?? 0} CVEs across {data?.categories_tracked ?? 0}{" "}
          categories
        </span>
      </div>

      {loading && <div className="panel-pad text-slate-500">Crunching asset health…</div>}

      {data && (
        <>
          <div className="analytics-card">
            <h3>Vulnerabilities by Technology Category</h3>
            <div className="mt-3">
              <ResponsiveContainer width="100%" height={360}>
                <BarChart data={chartData} layout="vertical" stackOffset="none">
                  <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                  <XAxis type="number" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="category"
                    stroke="#cbd5e1"
                    width={180}
                    tick={{ fontSize: 12 }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#0f1d3a",
                      border: "1px solid rgba(255,255,255,0.12)",
                      borderRadius: 8,
                      color: "#fff",
                    }}
                  />
                  <Legend wrapperStyle={{ color: "#cbd5e1" }} />
                  <Bar dataKey="Critical" fill="#ef4444" stackId="a" />
                  <Bar dataKey="High" fill="#f97316" stackId="a" />
                  <Bar dataKey="Medium" fill="#facc15" stackId="a" />
                  <Bar dataKey="Low" fill="#10b981" stackId="a" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-sentinel-border text-sm">
                <thead className="bg-sentinel-subtle">
                  <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Total</th>
                    <th className="px-4 py-3">Critical</th>
                    <th className="px-4 py-3">High</th>
                    <th className="px-4 py-3">Medium</th>
                    <th className="px-4 py-3">Low</th>
                    <th className="px-4 py-3">Exploited</th>
                    <th className="px-4 py-3">Weighted Risk</th>
                    <th className="px-4 py-3">Examples</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sentinel-border/70">
                  {data.categories.map((c) => (
                    <tr key={c.category} className="text-slate-600">
                      <td className="px-4 py-3 font-semibold text-sentinel-navyDark">
                        {c.category}
                      </td>
                      <td className="px-4 py-3">{c.total}</td>
                      <td className="px-4 py-3 text-red-500">{c.critical}</td>
                      <td className="px-4 py-3 text-orange-500">{c.high}</td>
                      <td className="px-4 py-3 text-yellow-500">{c.medium}</td>
                      <td className="px-4 py-3 text-emerald-500">{c.low}</td>
                      <td className="px-4 py-3 text-red-500">{c.exploited}</td>
                      <td className="px-4 py-3 font-semibold">{c.weighted_risk.toFixed(1)}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {c.sample_cves.map((cid) => (
                            <span
                              key={cid}
                              className="rounded-full border border-sentinel-border bg-white px-2 py-0.5 font-mono text-[10px] text-slate-500"
                            >
                              {cid}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
