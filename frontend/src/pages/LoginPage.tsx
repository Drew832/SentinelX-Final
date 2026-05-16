import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { useAuth } from "@/context/AuthContext";

/**
 * Login screen.
 *
 * The page keeps a branded navy hero (so the white SENTINEL + gold X
 * wordmark renders with proper contrast as required by the brand rules),
 * but the form fields themselves use a high-contrast white surface with
 * dark ink so usernames, passwords, and validation messages are
 * unambiguously readable.
 */
export default function LoginPage() {
  const { login, enterGuest } = useAuth();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: { pathname?: string } } };
  const from = location.state?.from?.pathname || "/dashboard";

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-gradient-to-br from-[#060d1e] via-sentinel-navyDark to-sentinel-navy px-4 py-10">
      {/* Decorative radar rings */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -bottom-32 -right-32 h-[500px] w-[500px] rounded-full border-2 border-sentinel-gold/10" />
        <div className="absolute -bottom-16 -right-16 h-[400px] w-[400px] rounded-full border-2 border-sentinel-gold/15" />
        <div className="absolute bottom-8 right-8 h-[280px] w-[280px] rounded-full border-2 border-sentinel-gold/20" />
        <div className="absolute -top-24 -left-24 h-[350px] w-[350px] rounded-full border border-sentinel-gold/5" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="relative z-10 w-full max-w-md overflow-hidden rounded-2xl border border-white/10 bg-white shadow-[0_18px_60px_rgba(0,0,0,0.5)]"
      >
        {/* Navy brand header — required for white "SENTINEL" + gold "X" contrast */}
        <div className="relative bg-gradient-to-br from-sentinel-navyDark via-sentinel-navy to-sentinel-navyDark px-8 py-7 text-center">
          <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-sentinel-gold/60 to-transparent" />
          <div className="mx-auto mb-3 flex items-center justify-center gap-3">
            <svg
              viewBox="0 0 120 120"
              className="h-14 w-14 drop-shadow-[0_0_20px_rgba(245,166,35,0.45)]"
              aria-hidden="true"
            >
              <g transform="translate(60,60)" fill="none" stroke="#F5A623">
                <circle r="52" strokeWidth="4" opacity="0.95" />
                <circle r="40" strokeWidth="2.5" opacity="0.75" />
                <circle r="28" strokeWidth="2" opacity="0.55" />
                <circle r="16" strokeWidth="1.5" opacity="0.4" />
                <circle r="4" fill="#F5A623" stroke="none" />
              </g>
            </svg>
            <div className="leading-tight">
              <div className="text-[34px] font-black tracking-tight">
                <span className="text-white drop-shadow-[0_1px_8px_rgba(255,255,255,0.18)]">
                  SENTINEL
                </span>
                <span className="ml-0.5 text-sentinel-gold drop-shadow-[0_0_12px_rgba(245,166,35,0.55)]">
                  X
                </span>
              </div>
              <div className="mt-0.5 text-[10px] font-bold uppercase tracking-[0.3em] text-slate-200/85">
                Detect · Prioritize · Remediate
              </div>
            </div>
          </div>
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-sentinel-gold">
            Secure Access Portal
          </p>
        </div>

        {/* Light form surface — high contrast for readability */}
        <div className="px-8 py-7">
          <h1 className="text-xl font-black text-sentinel-navyDark">Sign in</h1>
          <p className="mt-1 text-sm text-slate-500">
            Use your operator credentials to access SentinelX.
          </p>

          <form onSubmit={onSubmit} className="mt-5 space-y-4">
            <div>
              <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-600">
                Username or Email
              </label>
              <input
                autoFocus
                className="w-full rounded-lg border border-sentinel-border bg-white px-4 py-3 text-sm text-sentinel-ink placeholder:text-slate-400 focus:border-sentinel-navy focus:outline-none focus:ring-2 focus:ring-sentinel-navy/25 transition"
                placeholder="e.g. analyst@example.com"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-600">
                Password
              </label>
              <input
                type="password"
                className="w-full rounded-lg border border-sentinel-border bg-white px-4 py-3 text-sm text-sentinel-ink placeholder:text-slate-400 focus:border-sentinel-navy focus:outline-none focus:ring-2 focus:ring-sentinel-navy/25 transition"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {error && (
              <div className="rounded-lg border border-red-300 bg-red-50 px-3 py-2.5 text-sm font-medium text-red-700">
                {error}
              </div>
            )}
            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-gradient-to-r from-sentinel-gold to-sentinel-goldSoft px-4 py-3 text-sm font-bold text-sentinel-navyDark shadow-glow transition-all hover:brightness-110 hover:shadow-[0_0_40px_rgba(245,166,35,0.45)] focus:outline-none focus:ring-2 focus:ring-sentinel-gold/60 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <div className="mt-6 flex items-center justify-between text-sm">
            <Link
              to="/register"
              className="font-semibold text-sentinel-navyDark transition hover:text-sentinel-gold"
            >
              Create account
            </Link>
            <button
              onClick={() => {
                enterGuest();
                navigate("/dashboard");
              }}
              className="font-semibold text-sentinel-navyDark transition hover:text-sentinel-gold"
            >
              Continue as Guest →
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
