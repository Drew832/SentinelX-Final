import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { useAuth } from "@/context/AuthContext";

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
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-gradient-to-br from-[#060d1e] via-sentinel-navyDark to-sentinel-navy px-4">
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
        className="relative z-10 w-full max-w-md rounded-2xl border border-white/10 bg-white/[0.06] p-8 shadow-[0_8px_60px_rgba(0,0,0,0.45)] backdrop-blur-xl"
      >
        {/* Logo */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-5 flex items-center justify-center gap-3">
            <svg viewBox="0 0 120 120" className="h-16 w-16 drop-shadow-[0_0_20px_rgba(224,168,46,0.35)]" aria-hidden="true">
              <g transform="translate(60,60)" fill="none" stroke="#e0a82e">
                <circle r="52" strokeWidth="4" opacity="0.9" />
                <circle r="40" strokeWidth="2.5" opacity="0.7" />
                <circle r="28" strokeWidth="2" opacity="0.5" />
                <circle r="16" strokeWidth="1.5" opacity="0.35" />
                <circle r="4" fill="#e0a82e" stroke="none" />
              </g>
            </svg>
            <div className="leading-tight">
              <div className="text-[34px] font-black tracking-tight">
                <span className="text-white drop-shadow-[0_1px_8px_rgba(255,255,255,0.15)]">SENTINEL</span>
                <span className="ml-0.5 text-sentinel-gold drop-shadow-[0_0_12px_rgba(224,168,46,0.5)]">IX</span>
              </div>
              <div className="mt-0.5 text-[10px] font-bold uppercase tracking-[0.3em] text-slate-300/80">
                Detect · Prioritize · Remediate
              </div>
            </div>
          </div>
          <div className="mx-auto mb-3 h-px w-48 bg-gradient-to-r from-transparent via-sentinel-gold/40 to-transparent" />
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-sentinel-gold/80">
            Secure Access Portal
          </p>
        </div>

        <form onSubmit={onSubmit} className="space-y-5">
          <div>
            <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-200">
              Username or Email
            </label>
            <input
              autoFocus
              className="w-full rounded-lg border border-white/20 bg-white/[0.08] px-4 py-3 text-sm text-white placeholder:text-slate-400 focus:border-sentinel-gold/50 focus:bg-white/[0.12] focus:outline-none focus:ring-2 focus:ring-sentinel-gold/30 transition"
              placeholder="Enter your username or email"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-200">
              Password
            </label>
            <input
              type="password"
              className="w-full rounded-lg border border-white/20 bg-white/[0.08] px-4 py-3 text-sm text-white placeholder:text-slate-400 focus:border-sentinel-gold/50 focus:bg-white/[0.12] focus:outline-none focus:ring-2 focus:ring-sentinel-gold/30 transition"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && (
            <div className="rounded-lg border border-red-400/50 bg-red-500/20 px-3 py-2.5 text-sm font-medium text-red-200">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-gradient-to-r from-sentinel-gold to-sentinel-goldSoft px-4 py-3 text-sm font-bold text-sentinel-navyDark shadow-glow transition-all hover:shadow-[0_0_40px_rgba(224,168,46,0.4)] hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-sentinel-gold/60 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <div className="mt-6 flex items-center justify-between text-sm">
          <Link to="/register" className="font-medium text-slate-200 transition hover:text-sentinel-gold">
            Create account
          </Link>
          <button
            onClick={() => {
              enterGuest();
              navigate("/dashboard");
            }}
            className="font-medium text-slate-200 transition hover:text-sentinel-gold"
          >
            Continue as Guest →
          </button>
        </div>
      </motion.div>
    </div>
  );
}
