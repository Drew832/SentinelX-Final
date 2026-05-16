import { useState } from "react";
import clsx from "clsx";
import { policiesApi, type PolicyRecommendation } from "@/api/endpoints";

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const PRIORITY_STYLES: Record<string, string> = {
  HIGH: "bg-red-50 text-red-700 border-red-200",
  MEDIUM: "bg-amber-50 text-amber-700 border-amber-200",
  LOW: "bg-slate-100 text-slate-700 border-slate-200",
};

export default function PoliciesPage() {
  const [severity, setSeverity] = useState<string>("");
  const [onlyKev, setOnlyKev] = useState<boolean>(false);
  const [vendor, setVendor] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<{
    total_cves_evaluated: number;
    recommendations: PolicyRecommendation[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await policiesApi.recommend({
        severity: severity || undefined,
        only_kev: onlyKev,
        vendor: vendor || undefined,
        search: search || undefined,
      });
      setData(res);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "Failed to generate recommendations");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-heading">Policy Recommendations</h1>
          <div className="page-underline" />
          <p className="page-subtitle">
            Pick a CVE slice and we'll tell you which security policies need attention —
            with the exact keyword, CWE, or vendor signal that triggered each match.
          </p>
        </div>
      </div>

      <div className="panel-pad">
        <div className="grid gap-3 md:grid-cols-5">
          <div>
            <label className="label">Severity</label>
            <select
              className="input"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s || "All"}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Vendor</label>
            <input className="input" value={vendor} onChange={(e) => setVendor(e.target.value)} />
          </div>
          <div className="md:col-span-2">
            <label className="label">Keyword</label>
            <input className="input" value={search} onChange={(e) => setSearch(e.target.value)} />
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
        <div className="mt-3 flex justify-end">
          <button onClick={run} disabled={loading} className="btn-gold">
            {loading ? "Analysing…" : "Get Policy Recommendations"}
          </button>
        </div>
      </div>

      {error && <div className="panel-pad text-red-500">{error}</div>}

      {data && (
        <>
          <div className="panel-pad text-sm text-slate-500">
            Evaluated{" "}
            <span className="font-semibold text-sentinel-navyDark">
              {data.total_cves_evaluated.toLocaleString()}
            </span>{" "}
            CVE{data.total_cves_evaluated === 1 ? "" : "s"} against {data.recommendations.length}{" "}
            policy rule{data.recommendations.length === 1 ? "" : "s"}.
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            {data.recommendations.map((rec) => (
              <div key={rec.policy_name} className="panel p-5">
                <div className="flex items-start justify-between gap-3">
                  <h3 className="text-lg font-bold text-sentinel-navyDark">
                    {rec.policy_name}
                  </h3>
                  <span
                    className={clsx(
                      "badge border px-3 py-1",
                      PRIORITY_STYLES[rec.priority],
                    )}
                  >
                    {rec.priority}
                  </span>
                </div>
                <p className="mt-2 text-sm font-medium text-sentinel-navyDark">
                  Why: {rec.justification}
                </p>
                <p className="mt-1 text-sm text-slate-500">{rec.reason}</p>
                {rec.matched_terms?.length > 0 && (
                  <div className="mt-3">
                    <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
                      Triggered by
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {rec.matched_terms.slice(0, 8).map((t) => (
                        <span
                          key={t}
                          className="rounded-full border border-sentinel-border bg-sentinel-subtle px-2 py-0.5 font-mono text-[11px] text-sentinel-navyDark"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {rec.evidence?.length > 0 && (
                  <div className="mt-3">
                    <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
                      Sample evidence
                    </div>
                    <ul className="mt-1 space-y-1 text-xs">
                      {rec.evidence.slice(0, 4).map((e) => (
                        <li key={e.cve_id} className="text-slate-500">
                          <span className="font-mono font-semibold text-sentinel-navyDark">
                            {e.cve_id}
                          </span>
                          {" — "}
                          <span className="uppercase tracking-wider">{e.match_type}</span>
                          {e.matched_terms.length > 0 && (
                            <>
                              :{" "}
                              <span className="font-mono">{e.matched_terms.slice(0, 3).join(", ")}</span>
                            </>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                  <span className="rounded-full border border-sentinel-border bg-sentinel-subtle px-2 py-0.5 font-semibold text-sentinel-navyDark">
                    {rec.matched_cves} matching CVEs
                  </span>
                  {rec.example_cves.slice(0, 5).map((cid) => (
                    <span
                      key={cid}
                      className="rounded-full border border-sentinel-border bg-white px-2 py-0.5 font-mono text-slate-500"
                    >
                      {cid}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
