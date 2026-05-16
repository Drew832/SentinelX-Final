import { useEffect, useMemo, useState } from "react";
import * as Switch from "@radix-ui/react-switch";
import { motion } from "framer-motion";
import clsx from "clsx";
import { Link, useSearchParams } from "react-router-dom";
import { cveApi, policiesApi, type CVEListParams, type PolicyRecommendation } from "@/api/endpoints";
import type { CVE, CVEListResponse } from "@/types";
import SeverityBadge from "@/components/cve/SeverityBadge";
import KevBadge from "@/components/cve/KevBadge";
import { formatDate, nvdCveUrl, truncate } from "@/utils/format";

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

type ExtraFilters = {
  vendor?: string;
  start_date?: string;
  end_date?: string;
};

export default function CveExplorerPage() {
  const [search, setSearch] = useSearchParams();
  const focusId = search.get("focus");

  const [params, setParams] = useState<CVEListParams>({
    page: 1,
    page_size: 25,
    sort: "modified_desc",
    search: search.get("search") || undefined,
  });
  const [extra, setExtra] = useState<ExtraFilters>({});
  const [data, setData] = useState<CVEListResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<CVE | null>(null);
  const [recs, setRecs] = useState<PolicyRecommendation[] | null>(null);
  const [recsBusy, setRecsBusy] = useState(false);

  // Auto-open the detail modal when /cves?focus=CVE-… is hit (e.g. from the
  // dashboard Action Center) so the click feels like a deep link rather than
  // a generic search.
  useEffect(() => {
    if (!focusId) return;
    let cancelled = false;
    cveApi
      .get(focusId)
      .then((cve) => {
        if (!cancelled) setSelected(cve);
      })
      .catch(() => {
        // Fall back to populating the search box; the backend may not have
        // ingested this CVE yet.
        if (!cancelled) {
          setParams((p) => ({ ...p, search: focusId, page: 1 }));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [focusId]);

  const closeFocus = () => {
    setSelected(null);
    if (focusId) {
      const next = new URLSearchParams(search);
      next.delete("focus");
      setSearch(next, { replace: true });
    }
  };

  const totalPages = useMemo(
    () => (data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1),
    [data],
  );

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    cveApi
      .list(params)
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message || "Failed to fetch CVEs");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [params]);

  const update = (patch: Partial<CVEListParams>) =>
    setParams((p) => ({ ...p, ...patch, page: patch.page ?? 1 }));

  const exportHref = (format: "csv" | "xlsx") =>
    cveApi.exportUrl({
      format,
      severity: params.severity,
      search: params.search,
      only_kev: params.only_kev,
      min_score: params.min_score,
      max_score: params.max_score,
      vendor: extra.vendor,
      start_date: extra.start_date,
      end_date: extra.end_date,
    });

  const downloadExport = async (format: "csv" | "xlsx") => {
    const href = exportHref(format);
    const token = localStorage.getItem("sentinelx_token");
    const resp = await fetch(href, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelx-cves.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-heading">CVE Explorer</h1>
          <div className="page-underline" />
          <p className="page-subtitle">
            Search the live NVD + CISA KEV index. Filter by severity, vendor, or
            publication date, then export the exact slice you're working on.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            className="btn-secondary"
            disabled={recsBusy}
            onClick={async () => {
              setRecsBusy(true);
              try {
                const res = await policiesApi.recommend({
                  severity: params.severity,
                  only_kev: params.only_kev,
                  search: params.search,
                  vendor: extra.vendor,
                });
                setRecs(res.recommendations);
              } finally {
                setRecsBusy(false);
              }
            }}
          >
            {recsBusy ? "Analysing…" : "Get Policy Recommendations"}
          </button>
          <button className="btn-secondary" onClick={() => downloadExport("csv")}>
            Export CSV
          </button>
          <button className="btn-gold" onClick={() => downloadExport("xlsx")}>
            Export Excel
          </button>
        </div>
      </div>

      <div className="panel-pad">
        <div className="grid gap-3 md:grid-cols-12">
          <div className="md:col-span-4">
            <label className="label">Search</label>
            <input
              className="input"
              placeholder="CVE ID, vendor, keyword…"
              defaultValue={params.search || ""}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  update({ search: (e.target as HTMLInputElement).value || undefined });
                }
              }}
            />
          </div>
          <div className="md:col-span-2">
            <label className="label">Severity</label>
            <select
              className="input"
              value={params.severity || ""}
              onChange={(e) => update({ severity: e.target.value || undefined })}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s || "All"}</option>
              ))}
            </select>
          </div>
          <div className="md:col-span-2">
            <label className="label">Vendor</label>
            <input
              className="input"
              placeholder="e.g. microsoft"
              value={extra.vendor || ""}
              onChange={(e) => setExtra((x) => ({ ...x, vendor: e.target.value || undefined }))}
              onKeyDown={(e) => {
                if (e.key === "Enter") update({ page: 1 });
              }}
            />
          </div>
          <div className="md:col-span-2">
            <label className="label">Sort</label>
            <select
              className="input"
              value={params.sort || "modified_desc"}
              onChange={(e) => update({ sort: e.target.value })}
            >
              <option value="modified_desc">Last Modified</option>
              <option value="published_desc">Published</option>
              <option value="score_desc">CVSS Score</option>
            </select>
          </div>
          <div className="md:col-span-2">
            <label className="label">Published between</label>
            <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border border-sentinel-border bg-white px-2 py-1">
              <input
                type="date"
                className="min-w-0 flex-1 bg-transparent text-sm text-sentinel-ink outline-none"
                aria-label="From date"
                value={extra.start_date || ""}
                onChange={(e) => {
                  const v = e.target.value || undefined;
                  setExtra((x) => ({ ...x, start_date: v }));
                  update({ published_after: v, page: 1 });
                }}
              />
              <span className="text-xs text-slate-400">→</span>
              <input
                type="date"
                className="min-w-0 flex-1 bg-transparent text-sm text-sentinel-ink outline-none"
                aria-label="To date"
                value={extra.end_date || ""}
                onChange={(e) => {
                  const v = e.target.value || undefined;
                  setExtra((x) => ({ ...x, end_date: v }));
                  update({ published_before: v, page: 1 });
                }}
              />
            </div>
          </div>
        </div>

        <div className="mt-3 flex items-center gap-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-red-600">
            CISA KEV Only
          </span>
          <Switch.Root
            checked={!!params.only_kev}
            onCheckedChange={(v) => update({ only_kev: v })}
            className="relative h-5 w-9 rounded-full bg-slate-300 transition data-[state=checked]:bg-red-500"
          >
            <Switch.Thumb className="block h-4 w-4 translate-x-0.5 rounded-full bg-white shadow transition data-[state=checked]:translate-x-[18px]" />
          </Switch.Root>
          <span className="ml-auto text-xs text-slate-500">
            Filters apply to both the table and the Export buttons.
          </span>
        </div>
      </div>

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-sentinel-border text-sm">
            <thead className="bg-sentinel-subtle">
              <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3">CVE</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3">Vendors</th>
                <th className="px-4 py-3">Modified</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/70">
              {loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                    Loading…
                  </td>
                </tr>
              )}
              {error && !loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-red-500">
                    {error}
                  </td>
                </tr>
              )}
              {!loading && !error && data?.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                    No CVEs match the current filters. Try lowering filters or wait for the
                    next NVD ingest.
                  </td>
                </tr>
              )}
              {data?.items.map((cve) => (
                <motion.tr
                  key={cve.cve_id}
                  whileHover={{ backgroundColor: "rgba(28, 59, 122, 0.04)" }}
                  className={clsx(
                    "cursor-pointer transition",
                    cve.is_kev && "bg-red-50/60",
                  )}
                  onClick={() => setSelected(cve)}
                >
                  <td className="whitespace-nowrap px-4 py-3 font-mono font-semibold text-sentinel-navyDark">
                    <div className="flex items-center gap-2">
                      <a
                        href={nvdCveUrl(cve.cve_id)}
                        target="_blank"
                        rel="noreferrer"
                        className="hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {cve.cve_id}
                      </a>
                      {cve.is_kev && <KevBadge />}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={cve.cvss_v3_severity} score={cve.cvss_v3_score} />
                  </td>
                  <td className="max-w-xl px-4 py-3 text-slate-600">
                    {truncate(cve.description, 180)}
                  </td>
                  <td className="px-4 py-3 text-slate-600">
                    {(cve.vendors || []).slice(0, 3).join(", ") || "—"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-slate-500">
                    {formatDate(cve.last_modified_date)}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>

        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-sentinel-border px-4 py-3 text-xs text-slate-500">
            <div>
              {data.total.toLocaleString()} results · page {data.page} of {totalPages}
            </div>
            <div className="flex gap-2">
              <button
                className="btn-secondary"
                disabled={data.page <= 1}
                onClick={() => update({ page: data.page - 1 })}
              >
                ← Prev
              </button>
              <button
                className="btn-secondary"
                disabled={data.page >= totalPages}
                onClick={() => update({ page: data.page + 1 })}
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>

      {selected && <CveDetailModal cve={selected} onClose={closeFocus} />}

      {recs && (
        <div className="panel-pad">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-sentinel-navyDark">
              Policy Recommendations ({recs.length})
            </h2>
            <div className="flex gap-2">
              <Link to="/policies" className="btn-secondary">Open Policies Page</Link>
              <button className="btn-secondary" onClick={() => setRecs(null)}>Close</button>
            </div>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            {recs.slice(0, 6).map((r) => (
              <div key={r.policy_name} className="panel p-4">
                <div className="flex items-start justify-between gap-2">
                  <h3 className="font-bold text-sentinel-navyDark">
                    {r.policy_name}
                  </h3>
                  <span
                    className={
                      "badge border " +
                      (r.priority === "HIGH"
                        ? "bg-red-50 text-red-700 border-red-200"
                        : r.priority === "MEDIUM"
                        ? "bg-amber-50 text-amber-700 border-amber-200"
                        : "bg-slate-100 text-slate-600 border-slate-200")
                    }
                  >
                    {r.priority}
                  </span>
                </div>
                <p className="mt-2 text-xs font-medium text-sentinel-navyDark">
                  {r.justification}
                </p>
                <p className="mt-1 text-xs text-slate-500">{r.reason}</p>
                {r.matched_terms?.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {r.matched_terms.slice(0, 6).map((t) => (
                      <span
                        key={t}
                        className="rounded-full border border-sentinel-border bg-sentinel-subtle px-2 py-0.5 text-[10px] font-mono text-sentinel-navyDark"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
                <div className="mt-2 text-[11px] text-slate-400">
                  {r.matched_cves} matches ·{" "}
                  {r.example_cves.slice(0, 3).join(", ")}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CveDetailModal({ cve, onClose }: { cve: CVE; onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 px-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        className="panel max-h-[85vh] w-full max-w-3xl overflow-y-auto p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xl font-bold text-sentinel-navyDark">
              <a href={nvdCveUrl(cve.cve_id)} target="_blank" rel="noreferrer" className="hover:underline">
                {cve.cve_id}
              </a>
              {cve.is_kev && <KevBadge />}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <SeverityBadge severity={cve.cvss_v3_severity} score={cve.cvss_v3_score} />
              <span>Status: {cve.vuln_status || "—"}</span>
              <span>Source: {cve.source_identifier || "NVD"}</span>
            </div>
          </div>
          <button onClick={onClose} className="btn-secondary">Close</button>
        </div>

        {cve.description && (
          <p className="mb-4 leading-relaxed text-slate-700">{cve.description}</p>
        )}

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-sentinel-border bg-sentinel-subtle p-3">
            <div className="label">CVSS v3</div>
            <div className="mt-1 text-lg font-semibold text-sentinel-navyDark">
              {cve.cvss_v3_score ?? "—"} · {cve.cvss_v3_severity || "N/A"}
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-500">
              {cve.cvss_v3_vector || "—"}
            </div>
          </div>
          <div className="rounded-lg border border-sentinel-border bg-sentinel-subtle p-3">
            <div className="label">CVSS v2</div>
            <div className="mt-1 text-lg font-semibold text-sentinel-navyDark">
              {cve.cvss_v2_score ?? "—"} · {cve.cvss_v2_severity || "N/A"}
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-500">
              {cve.cvss_v2_vector || "—"}
            </div>
          </div>
        </div>

        {cve.is_kev && (
          <div className="mt-4 rounded-lg border border-red-300 bg-red-50 p-4">
            <div className="text-sm font-semibold text-red-700">CISA KEV Catalog Entry</div>
            <div className="mt-2 grid gap-2 text-xs text-slate-700 sm:grid-cols-2">
              <div>Vendor: {cve.kev_vendor_project || "—"}</div>
              <div>Product: {cve.kev_product || "—"}</div>
              <div>Added: {formatDate(cve.kev_date_added)}</div>
              <div>Due: {formatDate(cve.kev_due_date)}</div>
              <div>Ransomware use: {cve.kev_ransomware_use || "Unknown"}</div>
            </div>
            <div className="mt-3 text-xs text-red-700">
              <strong>Required action:</strong> {cve.kev_required_action || "—"}
            </div>
          </div>
        )}

        {cve.cwe_ids && cve.cwe_ids.length > 0 && (
          <div className="mt-4">
            <div className="label">CWE</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {cve.cwe_ids.map((c) => (
                <span
                  key={c}
                  className="badge bg-sentinel-subtle text-sentinel-ink border-sentinel-border"
                >
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}

        {cve.references && cve.references.length > 0 && (
          <div className="mt-4">
            <div className="label">References</div>
            <ul className="mt-1 space-y-1 text-xs">
              {cve.references.slice(0, 8).map((url) => (
                <li key={url}>
                  <a
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                    className="break-all text-sentinel-navy hover:underline"
                  >
                    {url}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </motion.div>
    </div>
  );
}
