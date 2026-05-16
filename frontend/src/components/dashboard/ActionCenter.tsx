import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { cveApi } from "@/api/endpoints";
import { SEVERITY_COLORS, truncate } from "@/utils/format";

interface TopCve {
  cve_id: string;
  cvss_v3_score: number | null;
  cvss_v3_severity: string | null;
  is_kev: boolean;
  is_exploited: boolean;
  priority_score: number;
  description: string;
  vendors: string[];
}

export default function ActionCenter({ criticality = 5 }: { criticality?: number }) {
  const [items, setItems] = useState<TopCve[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    cveApi.topPriority(criticality, 5).then((data) => {
      if (!cancelled) setItems(data as TopCve[]);
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [criticality]);

  return (
    <div className="analytics-card flex flex-col">
      <div className="flex items-center justify-between">
        <h3>Action Center</h3>
        <span className="text-[10px] font-bold uppercase tracking-widest text-sentinel-gold">
          Top 5 · Priority
        </span>
      </div>
      <p className="mt-1 text-xs text-slate-400">
        Tap any CVE to open its full record. Score combines CVSS, KEV status, and asset
        criticality (using {criticality}/5 here).
      </p>

      <div className="mt-4 flex-1 space-y-2">
        {loading && <div className="text-sm text-slate-400">Ranking threats…</div>}
        {!loading && items.length === 0 && (
          <div className="text-sm text-slate-400">No prioritised items yet — ingest data first.</div>
        )}
        {items.map((cve, idx) => {
          const color =
            SEVERITY_COLORS[(cve.cvss_v3_severity || "").toUpperCase()] || "#facc15";
          return (
            <Link
              key={cve.cve_id}
              to={`/cves?focus=${encodeURIComponent(cve.cve_id)}`}
              className="group block rounded-lg border border-white/10 bg-white/5 p-3 transition hover:bg-white/10"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-sentinel-gold">#{idx + 1}</span>
                  <span className="font-mono text-sm text-white">{cve.cve_id}</span>
                  {cve.is_exploited && (
                    <span className="badge-kev !py-0 !text-[10px]">Exploited</span>
                  )}
                </div>
                <div className="text-right">
                  <div className="text-xs uppercase tracking-wider text-slate-400">Priority</div>
                  <div className="text-sm font-bold" style={{ color }}>
                    {cve.priority_score.toFixed(2)}
                  </div>
                </div>
              </div>
              <p className="mt-1 line-clamp-2 text-xs text-slate-300">
                {truncate(cve.description, 140)}
              </p>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
