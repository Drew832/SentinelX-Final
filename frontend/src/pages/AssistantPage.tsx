import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import clsx from "clsx";
import { aiApi } from "@/api/endpoints";
import type { ChatMessage, ChatStructured, ChatStructuredCve } from "@/types";
import { useAuth } from "@/context/AuthContext";

const SUGGESTED = [
  "What is CVE-2024-3094?",
  "How many critical CVEs do we have?",
  "Show me actively exploited CVEs.",
  "What Microsoft CVEs should I worry about?",
  "What's the latest published CVE?",
];

interface BubbleMessage extends ChatMessage {
  structured?: ChatStructured | null;
  intent?: string | null;
}

function severityClass(sev?: string | null): string {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL":
      return "bg-red-500/15 text-red-700 border-red-300";
    case "HIGH":
      return "bg-orange-500/15 text-orange-700 border-orange-300";
    case "MEDIUM":
      return "bg-yellow-500/15 text-yellow-700 border-yellow-300";
    case "LOW":
      return "bg-emerald-500/15 text-emerald-700 border-emerald-300";
    default:
      return "bg-slate-100 text-slate-600 border-slate-200";
  }
}

function CveCard({ cve }: { cve: ChatStructuredCve }) {
  return (
    <div className="rounded-xl border border-sentinel-border bg-white p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-semibold text-sentinel-navyDark">
          {cve.cve_id}
        </span>
        <span className={clsx("badge border px-2 py-0.5 text-[10px]", severityClass(cve.cvss_v3_severity))}>
          {(cve.cvss_v3_severity || "N/A").toUpperCase()}
          {typeof cve.cvss_v3_score === "number" ? ` · ${cve.cvss_v3_score.toFixed(1)}` : ""}
        </span>
        {cve.is_kev && (
          <span className="badge-kev !py-0 !text-[10px]">⚡ KEV</span>
        )}
      </div>
      {cve.description && (
        <p className="mt-2 text-xs leading-relaxed text-slate-600">
          {cve.description.length > 280 ? cve.description.slice(0, 280) + "…" : cve.description}
        </p>
      )}
      {(cve.vendors?.length || cve.cwe_ids?.length) && (
        <div className="mt-2 flex flex-wrap gap-1 text-[10px]">
          {(cve.vendors || []).slice(0, 4).map((v) => (
            <span
              key={v}
              className="rounded-full border border-sentinel-border bg-sentinel-subtle px-2 py-0.5"
            >
              {v}
            </span>
          ))}
          {(cve.cwe_ids || []).slice(0, 3).map((c) => (
            <span
              key={c}
              className="rounded-full border border-sentinel-border bg-white px-2 py-0.5 font-mono"
            >
              {c}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function StructuredView({ payload }: { payload: ChatStructured }) {
  if (!payload) return null;
  const intent = payload.intent;

  if (intent === "count") {
    const sev = payload.severity || "tracked";
    return (
      <div className="rounded-xl border border-sentinel-border bg-white p-4">
        <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
          Count · {sev}{payload.only_kev ? " · KEV" : ""}
        </div>
        <div className="mt-1 text-4xl font-black text-sentinel-navyDark">
          {(payload.total ?? 0).toLocaleString()}
        </div>
      </div>
    );
  }

  if (intent === "asset_profile" && payload.profile) {
    const p = payload.profile;
    return (
      <div className="rounded-xl border border-sentinel-border bg-white p-4">
        <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
          Asset profile
        </div>
        <div className="mt-1 text-lg font-bold text-sentinel-navyDark">
          {p.name}
        </div>
        <div className="text-xs text-slate-500">
          {p.asset_name ? `${p.asset_name} · ` : ""}
          {p.environment} · Criticality {p.business_criticality}/5 ·
          {p.internet_exposed ? " Internet-exposed" : " Internal"}
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <div className="text-3xl font-black text-sentinel-navyDark">
            {p.risk_score?.toFixed(1) ?? "—"}
          </div>
          <div className="text-xs uppercase tracking-widest text-slate-500">
            {p.risk_label} · {p.matched_count} CVEs
          </div>
        </div>
      </div>
    );
  }

  if ((payload.cves?.length ?? 0) > 0) {
    return (
      <div className="grid gap-2 sm:grid-cols-2">
        {(payload.cves || []).map((c) => (
          <CveCard key={c.cve_id} cve={c} />
        ))}
      </div>
    );
  }

  return null;
}

export default function AssistantPage() {
  const { user } = useAuth();
  const [messages, setMessages] = useState<BubbleMessage[]>([
    {
      role: "assistant",
      content:
        "Hi — I'm SentinelX. Ask me about a specific CVE, a vendor, a severity rollup, or one of your asset profiles and I'll pull live context from the database.",
    },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  const send = async (text: string) => {
    if (!text.trim() || busy) return;
    const next: BubbleMessage[] = [...messages, { role: "user", content: text }];
    setMessages(next);
    setInput("");
    setBusy(true);
    try {
      const res = await aiApi.chat(
        text,
        next.slice(-10).map(({ role, content }) => ({ role, content })),
      );
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: res.answer,
          intent: res.intent ?? null,
          structured: res.structured ?? null,
        },
      ]);
    } catch (err: any) {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content:
            err?.response?.status === 401
              ? "Authentication required to use the AI assistant."
              : `Error contacting AI service: ${err?.message || "unknown"}`,
        },
      ]);
    } finally {
      setBusy(false);
    }
  };

  if (!user) {
    return (
      <div className="panel-pad text-center text-slate-500">
        Please sign in (Guest mode disabled) to use the AI Security Assistant.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="page-heading">AI Security Assistant</h1>
        <div className="page-underline" />
        <p className="page-subtitle">
          Ask in plain English — by CVE ID, vendor, severity, or asset profile.
          Answers are grounded in the CVEs you've ingested, so they reflect your environment.
        </p>
      </div>

      <div className="panel grid h-[70vh] grid-rows-[1fr_auto] overflow-hidden">
        <div ref={scrollRef} className="space-y-3 overflow-y-auto p-5">
          {messages.map((m, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className={clsx(
                "max-w-3xl rounded-2xl px-4 py-3 text-sm leading-relaxed",
                m.role === "user"
                  ? "ml-auto bg-sentinel-navy text-white"
                  : "bg-sentinel-subtle text-sentinel-ink border border-sentinel-border",
              )}
            >
              {m.intent && m.role === "assistant" && (
                <div className="mb-1 text-[10px] font-bold uppercase tracking-widest text-sentinel-gold">
                  {m.intent.replace("_", " ")}
                </div>
              )}
              <pre className="whitespace-pre-wrap break-words font-sans">{m.content}</pre>
              {m.structured && m.role === "assistant" && (
                <div className="mt-3 space-y-3">
                  <StructuredView payload={m.structured} />
                </div>
              )}
            </motion.div>
          ))}
          {busy && (
            <div className="max-w-3xl rounded-2xl border border-sentinel-border bg-sentinel-subtle px-4 py-3 text-sm text-slate-600">
              <span className="animate-pulse">SentinelX is checking the threat database…</span>
            </div>
          )}
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send(input);
          }}
          className="flex items-center gap-2 border-t border-sentinel-border p-3"
        >
          <input
            className="input flex-1"
            placeholder="e.g. CVE-2024-3094, microsoft, how many critical CVEs are exploited?"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <button type="submit" className="btn-gold" disabled={busy || !input.trim()}>
            Send
          </button>
        </form>
      </div>

      <div className="flex flex-wrap gap-2">
        {SUGGESTED.map((s) => (
          <button key={s} className="btn-secondary text-xs" onClick={() => send(s)}>
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}
