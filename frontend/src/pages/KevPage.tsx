import { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { motion } from "framer-motion";
import { kevApi } from "@/api/endpoints";
import SeverityBadge from "@/components/cve/SeverityBadge";
import { formatDate, truncate } from "@/utils/format";

export default function KevPage() {
  const [state, setState] = useState<Awaited<ReturnType<typeof kevApi.list>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [vendor, setVendor] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [ransomware, setRansomware] = useState<boolean>(false);
  const [page, setPage] = useState(1);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    kevApi
      .list({
        vendor: vendor || undefined,
        search: search.trim() || undefined,
        ransomware_only: ransomware,
        page,
        page_size: 25,
      })
      .then((data) => {
        if (!cancelled) setState(data);
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message || "Failed to load KEV catalog");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [vendor, search, ransomware, page]);

  const totalPages = useMemo(() => {
    if (!state) return 1;
    return Math.max(1, Math.ceil(state.total / state.page_size));
  }, [state]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-heading">CISA KEV Catalog</h1>
          <div className="page-underline" />
          <p className="page-subtitle">
            CVEs that CISA has seen weaponised in the real world. Patch these first —
            they show up in active campaigns, not theoretical research.
          </p>
        </div>
        <div className="flex items-center gap-3 text-right">
          <div>
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
              Actively exploited
            </div>
            <div className="text-2xl font-black text-sentinel-navyDark">
              {(state?.banner.total_kev ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
              Ransomware-linked
            </div>
            <div className="text-2xl font-black text-red-500">
              {(state?.banner.ransomware_linked ?? 0).toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      <div className="panel-pad">
        <div className="grid gap-3 md:grid-cols-12">
          <div className="md:col-span-6">
            <label className="label">Search</label>
            <input
              className="input"
              placeholder="CVE ID, vulnerability name, or keyword"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") setPage(1);
              }}
            />
          </div>
          <div className="md:col-span-4">
            <label className="label">Vendor</label>
            <select
              className="input"
              value={vendor}
              onChange={(e) => {
                setVendor(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All vendors</option>
              {(state?.vendors || []).map((v) => (
                <option key={v.vendor} value={v.vendor}>
                  {v.vendor} ({v.count})
                </option>
              ))}
            </select>
          </div>
          <div className="md:col-span-2 flex items-end">
            <label className="flex items-center gap-2 text-sm text-sentinel-ink">
              <input
                type="checkbox"
                checked={ransomware}
                onChange={(e) => {
                  setRansomware(e.target.checked);
                  setPage(1);
                }}
              />
              Ransomware only
            </label>
          </div>
        </div>
      </div>

      {error && <div className="panel-pad text-red-500">{error}</div>}

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-sentinel-border text-sm">
            <thead className="bg-sentinel-subtle">
              <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3">CVE</th>
                <th className="px-4 py-3">Vendor · Product</th>
                <th className="px-4 py-3">Vulnerability</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Ransomware</th>
                <th className="px-4 py-3">Added</th>
                <th className="px-4 py-3">Due</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/70">
              {loading && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                    Loading KEV catalog…
                  </td>
                </tr>
              )}
              {state?.items.map((c) => (
                <motion.tr
                  key={c.cve_id}
                  whileHover={{ backgroundColor: "rgba(224, 168, 46, 0.05)" }}
                  className="transition"
                >
                  <td className="whitespace-nowrap px-4 py-3 font-mono font-semibold text-sentinel-navyDark">
                    {c.cve_id}
                  </td>
                  <td className="px-4 py-3 text-slate-600">
                    <div className="font-semibold">{c.vendor || "—"}</div>
                    <div className="text-xs text-slate-500">{c.product}</div>
                  </td>
                  <td className="max-w-md px-4 py-3 text-slate-600">
                    <div className="font-semibold">{c.vulnerability_name || "—"}</div>
                    <div className="text-xs">{truncate(c.description, 140)}</div>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge
                      severity={c.cvss_v3_severity}
                      score={c.cvss_v3_score}
                    />
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {c.ransomware_use?.toLowerCase() === "known" ? (
                      <span className="badge-critical">Known</span>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                    {formatDate(c.date_added)}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                    {formatDate(c.due_date)}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>

        {state && state.total > 0 && (
          <div className="flex items-center justify-between border-t border-sentinel-border px-4 py-3 text-xs text-slate-500">
            <div>
              {state.total.toLocaleString()} entries · page {page} of {totalPages}
            </div>
            <div className="flex gap-2">
              <button
                className="btn-secondary"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                ← Prev
              </button>
              <button
                className="btn-secondary"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

