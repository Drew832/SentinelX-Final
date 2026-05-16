export default function ReportHeader({ title }: { title: string }) {
  return (
    <header className="relative overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-r from-[#5b3a2f] via-[#6a3a44] to-[#f59e0b] px-10 py-9 shadow-2xl print:rounded-none print:border-0">
      {/* Decorative rings */}
      <div className="pointer-events-none absolute -right-24 -top-24 h-[360px] w-[360px] rounded-full border-4 border-amber-300/40" />
      <div className="pointer-events-none absolute -right-10 -top-10 h-[260px] w-[260px] rounded-full border-2 border-amber-300/30" />
      <div className="pointer-events-none absolute -right-2 -top-2 h-[180px] w-[180px] rounded-full border border-amber-300/20" />

      <div className="relative flex flex-col items-center justify-center text-center">
        <div className="text-5xl font-black tracking-tight text-[#0b1734]">SENTINELX</div>
        <div className="mt-1 text-[11px] font-black uppercase tracking-[0.22em] text-[#0b1734]/80">
          DETECT. PRIORITIZE. REMEDIATE.
        </div>
        <div className="mt-6 text-2xl font-black tracking-tight text-white">Intelligence Report</div>
        <div className="mt-1 text-xs font-semibold uppercase tracking-[0.25em] text-white/80">
          {title}
        </div>
      </div>
    </header>
  );
}

