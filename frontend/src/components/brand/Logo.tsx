import clsx from "clsx";

interface Props {
  tagline?: boolean;
  compact?: boolean;
  dark?: boolean;
  className?: string;
}

export default function Logo({ tagline = false, compact = false, className }: Props) {
  return (
    <div className={clsx("flex items-center gap-3", className)}>
      <svg
        viewBox="0 0 120 120"
        className={compact ? "h-9 w-9" : "h-11 w-11"}
        aria-hidden="true"
      >
        <g transform="translate(60,60)" fill="none" stroke="#e0a82e">
          <circle r="52" strokeWidth="4" />
          <circle r="40" strokeWidth="2.5" opacity="0.75" />
          <circle r="28" strokeWidth="2" opacity="0.55" />
          <circle r="16" strokeWidth="1.5" opacity="0.4" />
          <circle r="3" fill="#e0a82e" stroke="none" />
        </g>
      </svg>
      <div className="leading-tight">
        <div
          className={clsx(
            "font-black tracking-tight",
            compact ? "text-xl" : "text-2xl",
          )}
        >
          <span className="text-sentinel-navyDark">SENTINEL</span>
          <span className="ml-0.5 text-sentinel-gold">IX</span>
        </div>
        {tagline && (
          <div className="mt-0.5 text-[10px] font-bold uppercase tracking-[0.3em] text-slate-500">
            Detect · Prioritize · Remediate
          </div>
        )}
      </div>
    </div>
  );
}
