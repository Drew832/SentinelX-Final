import { useEffect, useState } from "react";
import clsx from "clsx";
import { motion } from "framer-motion";
import { policyAiApi, profileApi } from "@/api/endpoints";
import type {
  Environment,
  OrgProfile,
  PrioritizedCVE,
  ProfilePolicyAiResponse,
  TechStackEntry,
} from "@/types";
import SeverityBadge from "@/components/cve/SeverityBadge";
import KevBadge from "@/components/cve/KevBadge";
import GenerateReportModal from "@/components/reports/GenerateReportModal";
import { nvdCveUrl, riskColor, truncate } from "@/utils/format";

const ENVIRONMENTS: Environment[] = ["PROD", "DEV", "TEST"];

export default function ProfilesPage() {
  const [profiles, setProfiles] = useState<OrgProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<OrgProfile | null>(null);
  const [matchedCves, setMatchedCves] = useState<PrioritizedCVE[]>([]);
  const [editing, setEditing] = useState<Partial<OrgProfile> | null>(null);
  const [showReport, setShowReport] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const list = await profileApi.list();
      setProfiles(list);
      if (list.length && !selected) {
        setSelected(list[0]);
      }
      setError(null);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load profiles");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    if (!selected) return;
    profileApi.cves(selected.id).then((res) => setMatchedCves(res.matched_cves));
  }, [selected]);

  const saveProfile = async () => {
    if (!editing) return;
    const payload = {
      name: editing.name || "",
      description: editing.description || "",
      tech_stack: editing.tech_stack || [],
      asset_name: editing.asset_name || undefined,
      environment: (editing.environment || "PROD") as Environment,
      internet_exposed: !!editing.internet_exposed,
      business_criticality: editing.business_criticality ?? 3,
    };
    try {
      if (editing.id) {
        const updated = await profileApi.update(editing.id, payload);
        setProfiles((ps) => ps.map((p) => (p.id === updated.id ? updated : p)));
        setSelected(updated);
      } else {
        const created = await profileApi.create(payload);
        setProfiles((ps) => [...ps, created]);
        setSelected(created);
      }
      setEditing(null);
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Save failed");
    }
  };

  const [actionMessage, setActionMessage] = useState<{
    kind: "ok" | "error";
    text: string;
  } | null>(null);

  useEffect(() => {
    if (!actionMessage) return;
    const t = window.setTimeout(() => setActionMessage(null), 4500);
    return () => window.clearTimeout(t);
  }, [actionMessage]);

  const rescore = async (p: OrgProfile) => {
    setActionMessage(null);
    try {
      const updated = await profileApi.rescore(p.id);
      setProfiles((ps) => ps.map((x) => (x.id === updated.id ? updated : x)));
      if (selected?.id === updated.id) {
        setSelected(updated);
        const res = await profileApi.cves(updated.id);
        setMatchedCves(res.matched_cves);
      }
      setActionMessage({
        kind: "ok",
        text: `Rescored "${updated.name}" — ${updated.matched_count} CVE${
          updated.matched_count === 1 ? "" : "s"
        } matched, risk ${updated.risk_label}.`,
      });
    } catch (e: any) {
      setActionMessage({
        kind: "error",
        text: e?.response?.data?.detail || e?.message || "Rescore failed",
      });
    }
  };

  const exportCsv = async (p: OrgProfile) => {
    setActionMessage(null);
    try {
      const token = localStorage.getItem("sentinelx_token");
      const resp = await fetch(profileApi.exportUrl(p.id), {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) throw new Error(`Export failed (${resp.status})`);
      const blob = await resp.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = href;
      a.download = `sentinelx-profile-${p.id}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(href);
      setActionMessage({ kind: "ok", text: `CSV downloaded for "${p.name}".` });
    } catch (e: any) {
      setActionMessage({
        kind: "error",
        text: e?.response?.data?.detail || e?.message || "CSV export failed",
      });
    }
  };

  const remove = async (p: OrgProfile) => {
    if (!confirm(`Delete profile "${p.name}"?`)) return;
    await profileApi.remove(p.id);
    setProfiles((ps) => ps.filter((x) => x.id !== p.id));
    if (selected?.id === p.id) setSelected(null);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-heading">Organisation Profiles</h1>
          <div className="page-underline" />
          <p className="page-subtitle">
            Tell SentinelX about the systems you actually run — vendor, product, environment,
            criticality. Each profile gets its own risk score, prioritised CVE list, and report.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            className="btn-gold"
            onClick={() =>
              setEditing({
                name: "",
                description: "",
                tech_stack: [{ vendor: "", product: "" }],
                asset_name: "",
                environment: "PROD",
                internet_exposed: false,
                business_criticality: 3,
              })
            }
          >
            + New profile
          </button>
        </div>
      </div>

      {error && <div className="panel-pad text-red-500">{error}</div>}
      {actionMessage && (
        <div
          className={clsx(
            "panel-pad text-sm",
            actionMessage.kind === "ok"
              ? "border-emerald-300 bg-emerald-50 text-emerald-800"
              : "border-red-300 bg-red-50 text-red-700",
          )}
        >
          {actionMessage.text}
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[320px_1fr]">
        <div className="space-y-3">
          {loading && profiles.length === 0 && (
            <div className="panel-pad text-slate-500">Loading profiles…</div>
          )}
          {profiles.length === 0 && !loading && (
            <div className="panel-pad text-slate-500">
              No profiles yet. Click "+ New profile" to describe your stack.
            </div>
          )}
          {profiles.map((p) => (
            <motion.button
              key={p.id}
              onClick={() => setSelected(p)}
              whileHover={{ y: -2 }}
              className={clsx(
                "panel w-full p-4 text-left transition",
                selected?.id === p.id && "ring-2 ring-sentinel-navy",
              )}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="font-semibold text-sentinel-navyDark">{p.name}</div>
                <span
                  className="badge"
                  style={{
                    background: riskColor(p.risk_label) + "22",
                    color: riskColor(p.risk_label),
                    borderColor: riskColor(p.risk_label) + "66",
                  }}
                >
                  {p.risk_label}
                </span>
              </div>
              <div className="mt-1 text-xs text-slate-500 line-clamp-2">
                {p.asset_name || p.description || "No asset"}
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1 text-[10px] uppercase tracking-wider">
                <span className="badge bg-sentinel-subtle text-sentinel-ink border-sentinel-border">
                  {p.environment}
                </span>
                {p.internet_exposed && (
                  <span className="badge bg-sentinel-gold/20 text-sentinel-goldDark border-sentinel-gold/40">
                    Internet
                  </span>
                )}
                <span className="badge bg-sentinel-subtle text-sentinel-ink border-sentinel-border">
                  Crit {p.business_criticality}/5
                </span>
              </div>
              <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
                <span>
                  Risk{" "}
                  <span className="font-semibold text-sentinel-navyDark">
                    {p.risk_score.toFixed(1)}
                  </span>
                </span>
                <span>{p.matched_count} CVEs</span>
              </div>
            </motion.button>
          ))}
        </div>

        <div className="space-y-4">
          {selected && (
            <ProfileDetail
              profile={selected}
              cves={matchedCves}
              onEdit={() => setEditing(selected)}
              onDelete={() => remove(selected)}
              onRescore={() => rescore(selected)}
              onReport={() => setShowReport(true)}
              onExportCsv={() => exportCsv(selected)}
            />
          )}
          {!selected && !loading && (
            <div className="panel-pad text-slate-500">
              Select a profile to see matched CVEs and risk breakdown.
            </div>
          )}
        </div>
      </div>

      {editing && (
        <ProfileEditor
          value={editing}
          onChange={setEditing}
          onCancel={() => setEditing(null)}
          onSave={saveProfile}
        />
      )}

      {showReport && <GenerateReportModal onClose={() => setShowReport(false)} />}
    </div>
  );
}

function ProfileDetail({
  profile,
  cves,
  onEdit,
  onDelete,
  onRescore,
  onReport,
  onExportCsv,
}: {
  profile: OrgProfile;
  cves: PrioritizedCVE[];
  onEdit: () => void;
  onDelete: () => void;
  onRescore: () => void;
  onReport: () => void;
  onExportCsv: () => void;
}) {
  const color = riskColor(profile.risk_label);
  const [policyTypes, setPolicyTypes] = useState<string[]>([]);
  const [policyType, setPolicyType] = useState("");
  const [policyCve, setPolicyCve] = useState("");
  const [policyResult, setPolicyResult] = useState<ProfilePolicyAiResponse | null>(null);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [policyErr, setPolicyErr] = useState<string | null>(null);

  useEffect(() => {
    policyAiApi
      .types()
      .then((t) => {
        setPolicyTypes(t);
        if (t.length) setPolicyType((p) => p || t[0]);
      })
      .catch(() => {
        const fallback = [
          "Access Control",
          "Network Security",
          "Data Protection",
          "Incident Response",
          "Application Security",
          "Physical & Supply Chain Security",
        ];
        setPolicyTypes(fallback);
        setPolicyType((p) => p || fallback[0]);
      });
  }, []);

  useEffect(() => {
    setPolicyCve((prev) => {
      if (prev && cves.some((c) => c.cve_id === prev)) return prev;
      return cves[0]?.cve_id || "";
    });
    setPolicyResult(null);
    setPolicyErr(null);
  }, [profile.id, cves]);

  const runPolicyAi = async () => {
    if (!policyCve || !policyType) return;
    setPolicyBusy(true);
    setPolicyErr(null);
    try {
      const res = await policyAiApi.recommendForProfile({
        profile_id: profile.id,
        cve_id: policyCve,
        policy_type: policyType,
      });
      setPolicyResult(res);
    } catch (e: any) {
      setPolicyResult(null);
      setPolicyErr(e?.response?.data?.detail || e?.message || "Could not generate recommendation");
    } finally {
      setPolicyBusy(false);
    }
  };

  return (
    <>
      <div className="panel-pad">
        <div className="flex flex-wrap items-start gap-6">
          <div className="flex-1 min-w-[260px]">
            <h2 className="text-2xl font-bold text-sentinel-navyDark">{profile.name}</h2>
            <p className="mt-1 text-sm text-slate-500">
              {profile.description || "No description"}
            </p>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
              <AssetChip label="Asset" value={profile.asset_name || "—"} />
              <AssetChip label="Environment" value={profile.environment} />
              <AssetChip
                label="Internet"
                value={profile.internet_exposed ? "Exposed" : "Internal"}
                highlight={profile.internet_exposed}
              />
              <AssetChip
                label="Criticality"
                value={`${profile.business_criticality}/5`}
              />
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {profile.tech_stack.map((e, i) => (
                <span
                  key={i}
                  className="badge bg-sentinel-subtle text-sentinel-ink border-sentinel-border"
                >
                  {e.vendor}
                  {e.product ? `:${e.product}` : ""}
                </span>
              ))}
            </div>
          </div>

          <div className="flex flex-col items-center justify-center rounded-xl border border-sentinel-border bg-sentinel-subtle px-6 py-4">
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">
              Risk Score
            </div>
            <div className="mt-1 text-5xl font-black" style={{ color }}>
              {profile.risk_score.toFixed(0)}
            </div>
            <div className="mt-0.5 text-xs font-semibold" style={{ color }}>
              {profile.risk_label}
            </div>
            <div className="mt-1 text-[11px] text-slate-500">
              {profile.matched_count} CVE{profile.matched_count === 1 ? "" : "s"}
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <button className="btn-secondary" onClick={onRescore}>Rescore</button>
            <button className="btn-secondary" onClick={onEdit}>Edit</button>
            <button className="btn-gold" onClick={onReport}>Generate Report</button>
            <button className="btn-secondary" onClick={onExportCsv}>Download CSV</button>
            <button className="btn-danger" onClick={onDelete}>Delete</button>
          </div>
        </div>
      </div>

      <div className="panel overflow-hidden">
        <div className="border-b border-sentinel-border px-5 py-3 text-sm font-semibold uppercase tracking-wider text-slate-600">
          Matched CVEs ({cves.length}) — sorted by priority_score
        </div>
        {cves.length === 0 ? (
          <div className="p-6 text-center text-slate-500">
            No CVEs matched. Add more vendors/products, or wait for the next NVD ingest.
          </div>
        ) : (
          <div className="max-h-[520px] overflow-y-auto">
            <table className="min-w-full divide-y divide-sentinel-border text-sm">
              <thead className="bg-sentinel-subtle text-left text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-4 py-2">CVE</th>
                  <th className="px-4 py-2">Priority</th>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">Exploited</th>
                  <th className="px-4 py-2">Description</th>
                  <th className="px-4 py-2">Vendors</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/70">
                {cves.map((c) => (
                  <tr key={c.cve_id} className={c.is_exploited ? "bg-red-50/60" : ""}>
                    <td className="px-4 py-2 font-mono font-semibold text-sentinel-navyDark">
                      <div className="flex items-center gap-2">
                        <a
                          href={nvdCveUrl(c.cve_id)}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {c.cve_id}
                        </a>
                        {c.is_kev && <KevBadge />}
                      </div>
                    </td>
                    <td className="px-4 py-2 font-semibold">{c.priority_score.toFixed(2)}</td>
                    <td className="px-4 py-2">
                      <SeverityBadge severity={c.cvss_v3_severity} score={c.cvss_v3_score} />
                    </td>
                    <td className="px-4 py-2">
                      {c.is_exploited ? (
                        <span className="badge-critical">Yes</span>
                      ) : (
                        <span className="text-slate-400">No</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-slate-600">{truncate(c.description, 140)}</td>
                    <td className="px-4 py-2 text-slate-500">
                      {(c.vendors || []).slice(0, 3).join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel-pad space-y-4">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-600">
            AI policy recommendation (profile CVE)
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            Choose a matched CVE and policy focus. Output explains why it maps to that control area.
          </p>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          <div>
            <label className="label">CVE</label>
            <select className="input" value={policyCve} onChange={(e) => setPolicyCve(e.target.value)}>
              {cves.length === 0 && <option value="">No matches</option>}
              {cves.map((c) => (
                <option key={c.cve_id} value={c.cve_id}>
                  {c.cve_id}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Policy type</label>
            <select className="input" value={policyType} onChange={(e) => setPolicyType(e.target.value)}>
              {policyTypes.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              type="button"
              className="btn-gold w-full"
              disabled={policyBusy || !policyCve}
              onClick={runPolicyAi}
            >
              {policyBusy ? "Generating…" : "Generate"}
            </button>
          </div>
        </div>
        {policyErr && <div className="text-sm text-red-600">{policyErr}</div>}
        {policyResult && (
          <div className="space-y-3 rounded-xl border border-sentinel-border bg-sentinel-subtle p-4 text-sm">
            <div className="text-[11px] uppercase tracking-wider text-slate-500">
              Model: {policyResult.model_used}
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-sentinel-goldDark">
                Recommendation
              </div>
              <p className="mt-1 whitespace-pre-wrap text-slate-700">{policyResult.recommendation}</p>
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-sentinel-goldDark">
                Why this maps
              </div>
              <p className="mt-1 whitespace-pre-wrap text-slate-700">{policyResult.justification}</p>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

function AssetChip({
  label,
  value,
  highlight = false,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div
      className={clsx(
        "rounded-lg border px-3 py-2",
        highlight
          ? "border-sentinel-gold/50 bg-sentinel-gold/10"
          : "border-sentinel-border bg-white",
      )}
    >
      <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">
        {label}
      </div>
      <div className="mt-0.5 text-sm font-semibold text-sentinel-navyDark">{value}</div>
    </div>
  );
}

function ProfileEditor({
  value,
  onChange,
  onCancel,
  onSave,
}: {
  value: Partial<OrgProfile>;
  onChange: (v: Partial<OrgProfile>) => void;
  onCancel: () => void;
  onSave: () => void;
}) {
  const techStack = value.tech_stack || [];

  const updateEntry = (i: number, patch: Partial<TechStackEntry>) => {
    const next = techStack.map((e, idx) => (idx === i ? { ...e, ...patch } : e));
    onChange({ ...value, tech_stack: next });
  };

  const addEntry = () =>
    onChange({ ...value, tech_stack: [...techStack, { vendor: "", product: "" }] });

  const removeEntry = (i: number) =>
    onChange({ ...value, tech_stack: techStack.filter((_, idx) => idx !== i) });

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
      <div className="panel w-full max-w-2xl p-6">
        <h3 className="text-xl font-bold text-sentinel-navyDark">
          {value.id ? "Edit profile" : "New profile"}
        </h3>

        <div className="mt-4 grid gap-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="label">Name</label>
              <input
                className="input"
                value={value.name || ""}
                onChange={(e) => onChange({ ...value, name: e.target.value })}
              />
            </div>
            <div>
              <label className="label">Asset name</label>
              <input
                className="input"
                placeholder="e.g. api-gw-prod"
                value={value.asset_name || ""}
                onChange={(e) => onChange({ ...value, asset_name: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="label">Description</label>
            <textarea
              className="input"
              rows={2}
              value={value.description || ""}
              onChange={(e) => onChange({ ...value, description: e.target.value })}
            />
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <label className="label">Environment</label>
              <select
                className="input"
                value={value.environment || "PROD"}
                onChange={(e) =>
                  onChange({ ...value, environment: e.target.value as Environment })
                }
              >
                {ENVIRONMENTS.map((env) => (
                  <option key={env} value={env}>{env}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label">Business criticality (1-5)</label>
              <input
                type="number"
                min={1}
                max={5}
                className="input"
                value={value.business_criticality ?? 3}
                onChange={(e) =>
                  onChange({
                    ...value,
                    business_criticality: Math.min(5, Math.max(1, Number(e.target.value))),
                  })
                }
              />
            </div>
            <div>
              <label className="label">Internet exposed</label>
              <label className="mt-2 flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!value.internet_exposed}
                  onChange={(e) =>
                    onChange({ ...value, internet_exposed: e.target.checked })
                  }
                />
                <span>Accessible from the public internet</span>
              </label>
            </div>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="label !mb-0">Tech stack (vendor / product)</label>
              <button onClick={addEntry} className="btn-secondary !px-3 !py-1 text-xs">
                + Add
              </button>
            </div>
            <div className="space-y-2">
              {techStack.length === 0 && (
                <div className="text-xs text-slate-500">
                  Add at least one vendor to compute a risk score.
                </div>
              )}
              {techStack.map((entry, i) => (
                <div key={i} className="flex items-center gap-2">
                  <input
                    className="input flex-1"
                    placeholder="Vendor (e.g. microsoft)"
                    value={entry.vendor}
                    onChange={(e) => updateEntry(i, { vendor: e.target.value })}
                  />
                  <input
                    className="input flex-1"
                    placeholder="Product (optional)"
                    value={entry.product || ""}
                    onChange={(e) => updateEntry(i, { product: e.target.value })}
                  />
                  <button
                    onClick={() => removeEntry(i)}
                    className="btn-secondary !px-2 !py-1 text-xs"
                  >
                    ✕
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button className="btn-secondary" onClick={onCancel}>Cancel</button>
          <button className="btn-gold" onClick={onSave}>Save profile</button>
        </div>
      </div>
    </div>
  );
}
