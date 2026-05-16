import { useState } from "react";
import { useAuth } from "@/context/AuthContext";

export default function AccountPage() {
  const { changePassword, user } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setMsg(null);
    if (next !== confirm) {
      setErr("New passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await changePassword(current, next);
      setMsg("Password updated successfully.");
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Could not update password.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-lg space-y-5">
      <div>
        <h1 className="page-heading">
          Account <span className="text-sentinel-gold">Security</span>
        </h1>
        <div className="page-underline" />
        <p className="page-subtitle">
          Signed in as <span className="font-semibold text-sentinel-navyDark">{user?.username}</span>. Use a
          strong passphrase (12+ characters with mixed character types).
        </p>
      </div>

      <div className="panel-pad">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-600">Change password</h2>
        <form className="mt-4 space-y-3" onSubmit={onSubmit}>
          <div>
            <label className="label">Current password</label>
            <input type="password" className="input" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </div>
          <div>
            <label className="label">New password</label>
            <input type="password" className="input" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} />
          </div>
          <div>
            <label className="label">Confirm new password</label>
            <input type="password" className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} required minLength={12} />
          </div>
          {err && <div className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700">{err}</div>}
          {msg && <div className="rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">{msg}</div>}
          <button className="btn-primary" type="submit" disabled={busy}>
            {busy ? "Updating…" : "Update password"}
          </button>
        </form>
      </div>
    </div>
  );
}
