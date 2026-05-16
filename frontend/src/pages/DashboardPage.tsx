import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { cveApi } from "@/api/endpoints";
import type { StatsResponse } from "@/types";
import { SEVERITY_COLORS, formatDate } from "@/utils/format";
import { useAuth } from "@/context/AuthContext";
import ActionCenter from "@/components/dashboard/ActionCenter";
import GenerateReportModal from "@/components/reports/GenerateReportModal";

const STAT_CARDS = [
  { key: "total_cves", label: "Total CVEs" },
  { key: "critical_count", label: "Critical" },
  { key: "high_count", label: "High" },
  { key: "medium_count", label: "Medium" },
  { key: "low_count", label: "Low" },
  { key: "unscored_count", label: "Unscored" },
] as const;

function SeverityPieTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number }>;
}) {
  if (!active || !payload?.length) return null;
  const row = payload[0];
  return (
    <div className="rounded-lg border border-white/20 bg-slate-950 px-3 py-2 text-sm shadow-xl">
      <div className="font-semibold text-white">{row.name}</div>
      <div className="text-slate-100">{row.value.toLocaleString()} CVEs</div>
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showReport, setShowReport] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const data = await cveApi.stats();
        if (mounted) setStats(data);
      } catch (e: any) {
        if (mounted) setError(e?.message || "Failed to load stats");
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 60_000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (loading) {
    return <div className="panel-pad text-slate-500">Loading intelligence feed…</div>;
  }
  if (error) {
    return <div className="panel-pad text-red-500">{error}</div>;
  }
  if (!stats) return null;

  return (
    <div className="space-y-8">
      {/* Hero header matching the wireframe — bold black title with gold underline */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="page-heading">Dashboard</h1>
          <div className="page-underline" />
          <p className="page-subtitle">
            {user ? `Hi ${user.username}, here's` : "Here's"} where your environment stands today.
            Threat feed last refreshed {formatDate(stats.last_ingest)}.
          </p>
        </div>
        <button onClick={() => setShowReport(true)} className="btn-gold">
          Generate Report
        </button>
      </div>

      {/* Overview section */}
      <section>
        <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-2xl font-black text-sentinel-navyDark">
              Overview
            </h2>
            <p className="text-xs uppercase tracking-widest text-slate-500">
              All CVEs ingested · Trend chart shows the last {stats.trend_window_days} days
            </p>
          </div>
          <div className="text-right text-xs text-slate-500">
            Severity buckets sum to{" "}
            <span className="font-semibold text-sentinel-navyDark">
              {stats.categorized_total.toLocaleString()}
            </span>
            {stats.unscored_count > 0 && (
              <>
                {" "}· {stats.unscored_count.toLocaleString()} unscored
              </>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
          {STAT_CARDS.map((c, idx) => (
            <motion.div
              key={c.key}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.05 }}
              className="stat-card"
            >
              <div className="stat-card__label">{c.label}</div>
              <div className="stat-card__value">
                {(stats[c.key as keyof StatsResponse] as number).toLocaleString()}
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Analytics row — wide + side card per the wireframe */}
      <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
        <div className="analytics-card">
          <h3>Last {stats.trend_window_days} days · CVE publication trend</h3>
          <div className="mt-4">
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={stats.trend_14d}>
                <defs>
                  <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#e0a82e" stopOpacity={0.55} />
                    <stop offset="100%" stopColor="#e0a82e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#9ca3af" tick={{ fontSize: 11 }} />
                <YAxis stroke="#9ca3af" tick={{ fontSize: 11 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "#0f1d3a",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: 8,
                    color: "#fff",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#e0a82e"
                  strokeWidth={2}
                  fill="url(#trendFill)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="analytics-card">
          <h3>Severity Distribution</h3>
          <div className="mt-4">
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={stats.severity_distribution}
                  dataKey="count"
                  nameKey="severity"
                  innerRadius={55}
                  outerRadius={88}
                  paddingAngle={2}
                >
                  {stats.severity_distribution.map((entry) => (
                    <Cell
                      key={entry.severity}
                      fill={SEVERITY_COLORS[entry.severity.toUpperCase()] || "#64748b"}
                    />
                  ))}
                </Pie>
                <Legend wrapperStyle={{ fontSize: 12, color: "#cbd5e1" }} />
                <Tooltip content={<SeverityPieTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
        <div className="analytics-card">
          <h3>Top 10 Affected Vendors</h3>
          <div className="mt-4">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={stats.top_vendors} layout="vertical">
                <XAxis type="number" stroke="#9ca3af" tick={{ fontSize: 11 }} />
                <YAxis
                  dataKey="vendor"
                  type="category"
                  stroke="#e2e8f0"
                  tick={{ fontSize: 12 }}
                  width={150}
                />
                <Tooltip
                  contentStyle={{
                    background: "#0f1d3a",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: 8,
                    color: "#fff",
                  }}
                />
                <Bar dataKey="count" fill="#e0a82e" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <ActionCenter />
      </div>

      {showReport && <GenerateReportModal onClose={() => setShowReport(false)} />}
    </div>
  );
}
