import clsx from "clsx";
import type { Severity } from "@/types";

const MAP: Record<string, string> = {
  CRITICAL: "badge-critical",
  HIGH: "badge-high",
  MEDIUM: "badge-medium",
  LOW: "badge-low",
};

export default function SeverityBadge({
  severity,
  score,
  className,
}: {
  severity?: Severity | string | null;
  score?: number | null;
  className?: string;
}) {
  const sev = (severity || "").toUpperCase();
  const cls = MAP[sev] || "badge bg-slate-700/40 text-slate-300";
  return (
    <span className={clsx(cls, className)}>
      {sev || "N/A"}
      {typeof score === "number" && <span className="ml-1 opacity-80">{score.toFixed(1)}</span>}
    </span>
  );
}
