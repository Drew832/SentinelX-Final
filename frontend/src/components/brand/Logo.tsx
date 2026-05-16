import clsx from "clsx";

interface Props {
  tagline?: boolean;
  compact?: boolean;
  /** Render the wordmark for dark surfaces (white SENTINEL + gold X). */
  dark?: boolean;
  className?: string;
}

/**
 * Official SentinelX wordmark.
 *
 * Brand rule (enforced project-wide):
 *   • SENTINEL is the contrast color (white on dark surfaces, navy on light)
 *   • X is ALWAYS gold (#F5A623 / sentinel-gold)
 *   • The mark is a single word: SENTINELX. No "IX" suffix, no numerals.
 *
 * The "X" sits inside a gold concentric-circle radar/target glyph that
 * doubles as the product icon.
 */
export default function Logo({
  tagline = false,
  compact = false,
  dark = false,
  className,
}: Props) {
  const sentinelColor = dark ? "text-white" : "text-sentinel-navyDark";
  const taglineColor = dark ? "text-slate-200/80" : "text-slate-500";

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
          <span className={sentinelColor}>SENTINEL</span>
          <span className="ml-0.5 text-sentinel-gold">X</span>
        </div>
        {tagline && (
          <div
            className={clsx(
              "mt-0.5 text-[10px] font-bold uppercase tracking-[0.3em]",
              taglineColor,
            )}
          >
            Detect · Prioritize · Remediate
          </div>
        )}
      </div>
    </div>
  );
}
