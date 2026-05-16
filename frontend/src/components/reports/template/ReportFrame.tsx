import type { ReactNode } from "react";

function WatermarkRings() {
  return (
    <svg
      className="pointer-events-none absolute -bottom-28 -right-40 h-[520px] w-[520px] opacity-25"
      viewBox="0 0 600 600"
      aria-hidden="true"
    >
      <g fill="none" stroke="#facc15" strokeWidth="4">
        <circle cx="330" cy="330" r="220" opacity="0.35" />
        <circle cx="330" cy="330" r="180" opacity="0.25" />
        <circle cx="330" cy="330" r="140" opacity="0.18" />
        <path
          d="M330 120a210 210 0 0 1 0 420"
          opacity="0.25"
        />
        <path
          d="M120 330a210 210 0 0 0 420 0"
          opacity="0.15"
        />
      </g>
    </svg>
  );
}

export default function ReportFrame({
  children,
  side,
}: {
  children: ReactNode;
  side?: ReactNode;
}) {
  return (
    <div className="relative min-h-screen bg-[#07122b] px-6 py-8 text-white print:bg-[#07122b] print:px-0 print:py-0">
      <div className="relative mx-auto w-full max-w-[980px] print:max-w-none">
        <WatermarkRings />

        <div className="grid gap-6 lg:grid-cols-[1fr_260px]">
          <div className="relative z-10">{children}</div>
          {side ? (
            <aside className="relative z-10">
              <div className="rounded-3xl bg-gradient-to-b from-orange-300/90 to-amber-700/80 p-6 text-slate-950 shadow-2xl print:shadow-none">
                {side}
              </div>
            </aside>
          ) : null}
        </div>

        <div className="mt-10 h-px w-full bg-amber-300/30" />
        <div className="mt-3 text-[11px] text-slate-300">SentinelX — Intelligence Report</div>
      </div>
    </div>
  );
}

