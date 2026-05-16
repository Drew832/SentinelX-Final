import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import clsx from "clsx";
import { profileApi, reportsApi } from "@/api/endpoints";
import type { OrgProfile } from "@/types";

type Format = "pdf" | "xlsx" | "csv";
type ReportType = "executive" | "technical";

function isoDay(d: Date) {
  return d.toISOString().slice(0, 10);
}

export default function GenerateReportModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState<OrgProfile[]>([]);
  const [profileId, setProfileId] = useState<number | null>(null);
  const [start, setStart] = useState(isoDay(new Date(Date.now() - 30 * 86400000)));
  const [end, setEnd] = useState(isoDay(new Date()));
  const [format, setFormat] = useState<Format>("pdf");
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    profileApi
      .list()
      .then((list) => {
        setProfiles(list);
        if (list.length) setProfileId(list[0].id);
      })
      .catch((e) =>
        setError(e?.response?.data?.detail || "Failed to load profiles. Sign in first."),
      )
      .finally(() => setLoading(false));
  }, []);

  const runExport = async () => {
    if (!profileId) return;
    setBusy(true);
    try {
      const url = reportsApi.downloadUrl({
        profile_id: profileId,
        start_date: start,
        end_date: end,
        report_type: reportType,
        format,
      });
      const token = localStorage.getItem("sentinelix_token");
      const resp = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) throw new Error(`Export failed (${resp.status})`);
      const blob = await resp.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = href;
      const ext = format === "xlsx" ? "xlsx" : format;
      a.download = `SentinelIX_CVE_Report_${end}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(href);
    } catch (e: any) {
      setError(e?.message || "Export failed");
    } finally {
      setBusy(false);
    }
  };

  const viewReport = () => {
    if (!profileId) return;
    navigate(
      `/reports?profile_id=${profileId}&start_date=${start}&end_date=${end}&report_type=${reportType}`,
    );
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        className="panel w-full max-w-lg p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-xl font-black text-sentinel-navyDark">
          Generate Report
        </h3>
        <p className="mt-1 text-sm text-slate-500">
          Export executive briefings or full technical drill-downs, scoped to a profile and date
          range.
        </p>

        {loading ? (
          <div className="mt-6 text-slate-500">Loading profiles…</div>
        ) : profiles.length === 0 ? (
          <div className="mt-4 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800">
            You don't have any organisation profiles yet. Create one from the Org Profiles page.
          </div>
        ) : (
          <div className="mt-5 space-y-4">
            <div>
              <label className="label">Profile</label>
              <select
                className="input"
                value={profileId ?? ""}
                onChange={(e) => setProfileId(Number(e.target.value))}
              >
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} · {p.environment} · criticality {p.business_criticality}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="label">Report type</label>
              <div className="flex gap-2">
                {(["executive", "technical"] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setReportType(t)}
                    className={clsx(
                      "flex-1 rounded-lg border px-3 py-2 text-sm font-semibold uppercase transition",
                      reportType === t
                        ? "border-sentinel-navy bg-sentinel-navy text-white"
                        : "border-sentinel-border bg-white text-sentinel-ink hover:bg-sentinel-subtle",
                    )}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Start date</label>
                <input
                  type="date"
                  className="input"
                  value={start}
                  onChange={(e) => setStart(e.target.value)}
                />
              </div>
              <div>
                <label className="label">End date</label>
                <input
                  type="date"
                  className="input"
                  value={end}
                  onChange={(e) => setEnd(e.target.value)}
                />
              </div>
            </div>

            <div>
              <label className="label">Export format</label>
              <div className="flex gap-2">
                {(["pdf", "xlsx", "csv"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFormat(f)}
                    className={clsx(
                      "flex-1 rounded-lg border px-3 py-2 text-sm font-semibold uppercase transition",
                      format === f
                        ? "border-sentinel-navy bg-sentinel-navy text-white"
                        : "border-sentinel-border bg-white text-sentinel-ink hover:bg-sentinel-subtle",
                    )}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            {error && (
              <div className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700">
                {error}
              </div>
            )}
          </div>
        )}

        <div className="mt-6 flex flex-wrap justify-end gap-2">
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          {profiles.length > 0 && (
            <>
              <button className="btn-secondary" onClick={viewReport} disabled={busy || !profileId}>
                View in browser
              </button>
              <button className="btn-gold" onClick={runExport} disabled={busy || !profileId}>
                {busy ? "Exporting…" : `Download ${format.toUpperCase()}`}
              </button>
            </>
          )}
        </div>
      </motion.div>
    </div>
  );
}
