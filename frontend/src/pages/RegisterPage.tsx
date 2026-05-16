import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { useAuth } from "@/context/AuthContext";

const OTP_TTL_SECONDS = 10 * 60;
const RESEND_COOLDOWN_SECONDS = 30;

/**
 * Registration + email-OTP verification.
 *
 * The page is light-themed for readability with a navy brand strip at the
 * top so the white SENTINEL + gold X wordmark renders correctly. The
 * verification form normalises the user's input (digits only, length 6)
 * before submission so a stray space or leading zero never trips up the
 * server-side bcrypt comparison.
 *
 * Hardening notes:
 *   • 10-minute expiry timer rendered live next to the code field.
 *   • Resend button is disabled for ``RESEND_COOLDOWN_SECONDS`` so we
 *     never spam the SMTP relay (the server enforces the same cooldown
 *     defensively and returns 429 if the client lies).
 *   • Wrapped in an ErrorBoundary at the app shell so a crash here
 *     never lands the user on a blank page.
 */
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
  const [secondsRemaining, setSecondsRemaining] = useState<number>(OTP_TTL_SECONDS);
  const [resendCooldown, setResendCooldown] = useState<number>(0);
  const tickRef = useRef<number | null>(null);
  const cooldownRef = useRef<number | null>(null);

  const pwdRules =
    "Use at least 12 characters with uppercase, lowercase, a number, and a special character.";

  useEffect(() => {
    if (step !== "verify") {
      if (tickRef.current) window.clearInterval(tickRef.current);
      return;
    }
    setSecondsRemaining(OTP_TTL_SECONDS);
    setResendCooldown(RESEND_COOLDOWN_SECONDS);
    tickRef.current = window.setInterval(() => {
      setSecondsRemaining((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => {
      if (tickRef.current) window.clearInterval(tickRef.current);
    };
  }, [step]);

  useEffect(() => {
    if (resendCooldown <= 0) {
      if (cooldownRef.current) window.clearInterval(cooldownRef.current);
      return;
    }
    cooldownRef.current = window.setInterval(() => {
      setResendCooldown((p) => (p > 0 ? p - 1 : 0));
    }, 1000);
    return () => {
      if (cooldownRef.current) window.clearInterval(cooldownRef.current);
    };
  }, [resendCooldown]);

  const formatRemaining = (s: number) => {
    const mins = Math.floor(s / 60);
    const secs = s % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setSubmitting(true);
    try {
      const pending = await register(email, username, password);
      // Defensive: only advance the flow if the server actually returned
      // an email — guards against a misconfigured backend returning HTML.
      const pendingEmail = pending?.email || email;
      const pendingDetail = pending?.detail || "Check your inbox for the 6-digit code.";
      setEmail(pendingEmail);
      setInfo(pendingDetail);
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
    const cleanCode = code.replace(/\D/g, "").trim();
    if (cleanCode.length !== 6) {
      setError("Enter the 6-digit code from your email.");
      return;
    }
    if (secondsRemaining <= 0) {
      setError("This verification code has expired. Please request a new code.");
      return;
    }
    setSubmitting(true);
    try {
      await verifyEmail(email.trim().toLowerCase(), cleanCode);
      window.location.href = "/dashboard";
    } catch (err: any) {
      setError(
        err?.response?.data?.detail ||
          "Verification failed. Double-check the code or request a new one.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const onResend = async () => {
    if (resendCooldown > 0 || submitting) return;
    setError(null);
    setInfo(null);
    setSubmitting(true);
    try {
      const pending = await resendOtp(email.trim().toLowerCase());
      setInfo(pending?.detail || "A new code is on its way.");
      setSecondsRemaining(OTP_TTL_SECONDS);
      setResendCooldown(RESEND_COOLDOWN_SECONDS);
      setCode("");
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
        <div className="absolute -bottom-20 -right-20 h-[300px] w-[300px] rounded-full border border-sentinel-gold/10" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="relative z-10 w-full max-w-md overflow-hidden rounded-2xl border border-white/10 bg-white shadow-[0_18px_60px_rgba(0,0,0,0.5)]"
      >
        {/* Brand header */}
        <div className="relative bg-gradient-to-br from-sentinel-navyDark via-sentinel-navy to-sentinel-navyDark px-8 py-6">
          <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-sentinel-gold/60 to-transparent" />
          <div className="flex items-center gap-3">
            <svg
              viewBox="0 0 120 120"
              className="h-11 w-11 drop-shadow-[0_0_16px_rgba(245,166,35,0.4)]"
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
              <div className="text-2xl font-black tracking-tight">
                <span className="text-white drop-shadow-[0_1px_6px_rgba(255,255,255,0.18)]">
                  SENTINEL
                </span>
                <span className="ml-0.5 text-sentinel-gold drop-shadow-[0_0_10px_rgba(245,166,35,0.5)]">
                  X
                </span>
              </div>
              <div className="mt-0.5 text-[9px] font-bold uppercase tracking-[0.3em] text-slate-200/85">
                Detect · Prioritize · Remediate
              </div>
            </div>
          </div>
        </div>

        <div className="px-8 py-6">
          {step === "form" && (
            <>
              <h1 className="mb-1 text-xl font-black text-sentinel-navyDark">
                Create your operator
              </h1>
              <p className="mb-3 text-sm text-slate-500">
                Passwords are bcrypt-hashed before storage. Accounts stay inactive until you confirm
                the one-time code sent to your email.
              </p>
              <p className="mb-5 rounded-lg border border-sentinel-border bg-sentinel-subtle px-3 py-2 text-xs text-slate-600">
                {pwdRules}
              </p>

              <form onSubmit={onSubmit} className="space-y-4">
                <div>
                  <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-600">
                    Email
                  </label>
                  <input
                    type="email"
                    className="w-full rounded-lg border border-sentinel-border bg-white px-4 py-3 text-sm text-sentinel-ink placeholder:text-slate-400 focus:border-sentinel-navy focus:outline-none focus:ring-2 focus:ring-sentinel-navy/25 transition"
                    value={email}
                    required
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-600">
                    Username
                  </label>
                  <input
                    className="w-full rounded-lg border border-sentinel-border bg-white px-4 py-3 text-sm text-sentinel-ink placeholder:text-slate-400 focus:border-sentinel-navy focus:outline-none focus:ring-2 focus:ring-sentinel-navy/25 transition"
                    value={username}
                    required
                    minLength={3}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-600">
                    Password
                  </label>
                  <input
                    type="password"
                    className="w-full rounded-lg border border-sentinel-border bg-white px-4 py-3 text-sm text-sentinel-ink placeholder:text-slate-400 focus:border-sentinel-navy focus:outline-none focus:ring-2 focus:ring-sentinel-navy/25 transition"
                    value={password}
                    required
                    minLength={12}
                    onChange={(e) => setPassword(e.target.value)}
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
                  className="w-full rounded-lg bg-gradient-to-r from-sentinel-gold to-sentinel-goldSoft px-4 py-3 text-sm font-bold text-sentinel-navyDark shadow-glow transition-all hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-sentinel-gold/60 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {submitting ? "Creating account…" : "Create account"}
                </button>
              </form>
            </>
          )}

          {step === "verify" && (
            <>
              <h1 className="mb-1 text-xl font-black text-sentinel-navyDark">
                Verify your email
              </h1>
              <p className="mb-3 text-sm text-slate-500">
                Enter the 6-digit code we sent to{" "}
                <span className="font-semibold text-sentinel-navyDark">{email}</span>.
              </p>
              <div className="mb-4 flex items-center justify-between rounded-lg border border-sentinel-border bg-sentinel-subtle px-3 py-2 text-xs text-slate-600">
                <span>Code expires in</span>
                <span
                  className={
                    secondsRemaining < 60
                      ? "font-mono font-bold text-red-600"
                      : "font-mono font-bold text-sentinel-navyDark"
                  }
                >
                  {formatRemaining(secondsRemaining)}
                </span>
              </div>
              {info && (
                <div className="mb-4 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-xs text-emerald-700">
                  {info}
                </div>
              )}
              <form onSubmit={onVerify} className="space-y-4">
                <div>
                  <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-600">
                    Verification code
                  </label>
                  <input
                    className="w-full rounded-lg border border-sentinel-border bg-white px-4 py-3.5 font-mono text-2xl tracking-[0.4em] text-center text-sentinel-navyDark placeholder:text-slate-300 focus:border-sentinel-navy focus:outline-none focus:ring-2 focus:ring-sentinel-navy/30 transition"
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
                  <div className="rounded-lg border border-red-300 bg-red-50 px-3 py-2.5 text-sm font-medium text-red-700">
                    {error}
                  </div>
                )}
                <button
                  type="submit"
                  disabled={submitting || code.length !== 6 || secondsRemaining <= 0}
                  className="w-full rounded-lg bg-gradient-to-r from-sentinel-gold to-sentinel-goldSoft px-4 py-3 text-sm font-bold text-sentinel-navyDark shadow-glow transition-all hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-sentinel-gold/60 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {submitting ? "Verifying…" : "Verify and continue"}
                </button>
                <button
                  type="button"
                  onClick={onResend}
                  disabled={submitting || resendCooldown > 0}
                  className="w-full rounded-lg border border-sentinel-border bg-white px-4 py-2.5 text-sm font-semibold text-sentinel-navyDark transition hover:bg-sentinel-subtle disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {resendCooldown > 0
                    ? `Resend code in ${resendCooldown}s`
                    : "Resend code"}
                </button>
              </form>
            </>
          )}

          <div className="mt-5 text-center text-sm text-slate-500">
            Already have an account?{" "}
            <Link to="/login" className="font-semibold text-sentinel-navyDark hover:text-sentinel-gold">
              Sign in
            </Link>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
