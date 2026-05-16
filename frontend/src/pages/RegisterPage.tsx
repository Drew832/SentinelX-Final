import { useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { useAuth } from "@/context/AuthContext";

export default function RegisterPage() {
  const { register, verifyEmail, resendOtp } = useAuth();

  const [step, setStep] = useState<"form" | "verify">("form");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const pwdRules =
    "Use at least 12 characters with uppercase, lowercase, a number, and a special character.";

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setSubmitting(true);
    try {
      const pending = await register(email, username, password);
      setEmail(pending.email);
      setInfo(pending.detail);
      setStep("verify");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Registration failed");
    } finally {
      setSubmitting(false);
    }
  };

  const onVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setSubmitting(true);
    try {
      await verifyEmail(email, code.trim());
      window.location.href = "/dashboard";
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Verification failed");
    } finally {
      setSubmitting(false);
    }
  };

  const onResend = async () => {
    setError(null);
    setInfo(null);
    setSubmitting(true);
    try {
      const pending = await resendOtp(email);
      setInfo(pending.detail);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Could not resend code");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-gradient-to-br from-[#060d1e] via-sentinel-navyDark to-sentinel-navy px-4 py-10">
      {/* Decorative radar rings */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -top-32 -left-32 h-[500px] w-[500px] rounded-full border-2 border-sentinel-gold/10" />
        <div className="absolute -top-16 -left-16 h-[400px] w-[400px] rounded-full border-2 border-sentinel-gold/15" />
        <div className="absolute -bottom-20 -right-20 h-[300px] w-[300px] rounded-full border border-sentinel-gold/8" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="relative z-10 w-full max-w-md rounded-2xl border border-white/10 bg-white/[0.06] p-8 shadow-[0_8px_60px_rgba(0,0,0,0.45)] backdrop-blur-xl"
      >
        <div className="mb-6 flex items-center gap-3">
          <svg viewBox="0 0 120 120" className="h-11 w-11 drop-shadow-[0_0_16px_rgba(224,168,46,0.3)]" aria-hidden="true">
            <g transform="translate(60,60)" fill="none" stroke="#e0a82e">
              <circle r="52" strokeWidth="4" opacity="0.9" />
              <circle r="40" strokeWidth="2.5" opacity="0.7" />
              <circle r="28" strokeWidth="2" opacity="0.5" />
              <circle r="16" strokeWidth="1.5" opacity="0.35" />
              <circle r="4" fill="#e0a82e" stroke="none" />
            </g>
          </svg>
          <div className="leading-tight">
            <div className="text-2xl font-black tracking-tight">
              <span className="text-white drop-shadow-[0_1px_6px_rgba(255,255,255,0.12)]">SENTINEL</span>
              <span className="ml-0.5 text-sentinel-gold drop-shadow-[0_0_10px_rgba(224,168,46,0.4)]">IX</span>
            </div>
            <div className="mt-0.5 text-[9px] font-bold uppercase tracking-[0.3em] text-slate-300/80">
              Detect · Prioritize · Remediate
            </div>
          </div>
        </div>

        {step === "form" && (
          <>
            <h1 className="mb-1 text-2xl font-black text-white">
              Create your operator
            </h1>
            <p className="mb-4 text-sm text-slate-300">
              Passwords are bcrypt-hashed before storage. Accounts stay inactive until you confirm the
              one-time code sent to your email.
            </p>
            <p className="mb-6 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-300">
              {pwdRules}
            </p>

            <form onSubmit={onSubmit} className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-200">Email</label>
                <input
                  type="email"
                  className="w-full rounded-lg border border-white/20 bg-white/[0.08] px-4 py-3 text-sm text-white placeholder:text-slate-400 focus:border-sentinel-gold/50 focus:bg-white/[0.12] focus:outline-none focus:ring-2 focus:ring-sentinel-gold/30 transition"
                  value={email}
                  required
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-200">Username</label>
                <input
                  className="w-full rounded-lg border border-white/20 bg-white/[0.08] px-4 py-3 text-sm text-white placeholder:text-slate-400 focus:border-sentinel-gold/50 focus:bg-white/[0.12] focus:outline-none focus:ring-2 focus:ring-sentinel-gold/30 transition"
                  value={username}
                  required
                  minLength={3}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-200">Password</label>
                <input
                  type="password"
                  className="w-full rounded-lg border border-white/20 bg-white/[0.08] px-4 py-3 text-sm text-white placeholder:text-slate-400 focus:border-sentinel-gold/50 focus:bg-white/[0.12] focus:outline-none focus:ring-2 focus:ring-sentinel-gold/30 transition"
                  value={password}
                  required
                  minLength={12}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              {error && (
                <div className="rounded-lg border border-red-400/50 bg-red-500/20 px-3 py-2.5 text-sm font-medium text-red-200">
                  {error}
                </div>
              )}
              <button type="submit" disabled={submitting} className="w-full rounded-lg bg-gradient-to-r from-sentinel-gold to-sentinel-goldSoft px-4 py-3 text-sm font-bold text-sentinel-navyDark shadow-glow transition-all hover:shadow-[0_0_40px_rgba(224,168,46,0.4)] hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-sentinel-gold/60 disabled:cursor-not-allowed disabled:opacity-50">
                {submitting ? "Creating account…" : "Create account"}
              </button>
            </form>
          </>
        )}

        {step === "verify" && (
          <>
            <h1 className="mb-1 text-2xl font-black text-white">
              Verify your email
            </h1>
            <p className="mb-4 text-sm text-slate-300">
              Enter the 6-digit code we sent to{" "}
              <span className="font-semibold text-sentinel-gold">{email}</span>.
            </p>
            <p className="mb-4 text-xs text-slate-400">
              This code will expire in 15 minutes. Check your spam folder if you don't see it.
            </p>
            {info && (
              <div className="mb-4 rounded-lg border border-emerald-400/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200">
                {info}
              </div>
            )}
            <form onSubmit={onVerify} className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-200">Verification code</label>
                <input
                  className="w-full rounded-lg border border-white/20 bg-white/[0.08] px-4 py-3.5 font-mono text-2xl tracking-[0.4em] text-center text-white placeholder:text-slate-500 focus:border-sentinel-gold/50 focus:bg-white/[0.12] focus:outline-none focus:ring-2 focus:ring-sentinel-gold/30 transition"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  maxLength={6}
                  placeholder="000000"
                  required
                />
              </div>
              {error && (
                <div className="rounded-lg border border-red-400/50 bg-red-500/20 px-3 py-2.5 text-sm font-medium text-red-200">
                  {error}
                </div>
              )}
              <button type="submit" disabled={submitting} className="w-full rounded-lg bg-gradient-to-r from-sentinel-gold to-sentinel-goldSoft px-4 py-3 text-sm font-bold text-sentinel-navyDark shadow-glow transition-all hover:shadow-[0_0_40px_rgba(224,168,46,0.4)] hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-sentinel-gold/60 disabled:cursor-not-allowed disabled:opacity-50">
                {submitting ? "Verifying…" : "Verify and continue"}
              </button>
              <button type="button" onClick={onResend} disabled={submitting} className="w-full rounded-lg border border-white/20 bg-white/[0.06] px-4 py-2.5 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.12] disabled:cursor-not-allowed disabled:opacity-50">
                Resend code
              </button>
            </form>
          </>
        )}

        <div className="mt-5 text-center text-sm text-slate-300">
          Already have an account?{" "}
          <Link to="/login" className="font-semibold text-sentinel-gold hover:underline">
            Sign in
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
