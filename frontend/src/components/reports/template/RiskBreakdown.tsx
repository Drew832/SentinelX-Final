type Card = {
  label: string;
  count: number;
  tone: "low" | "medium" | "high";
};

const TONES: Record<Card["tone"], { bg: string; fg: string; border: string }> = {
  low: {
    bg: "bg-gradient-to-br from-emerald-500/80 to-emerald-700/70",
    fg: "text-slate-950",
    border: "border-emerald-200/40",
  },
  medium: {
    bg: "bg-gradient-to-br from-orange-300/90 to-amber-600/70",
    fg: "text-slate-950",
    border: "border-amber-200/40",
  },
  high: {
    bg: "bg-gradient-to-br from-red-500/80 to-rose-800/70",
    fg: "text-white",
    border: "border-red-200/25",
  },
};

export default function RiskBreakdown({ cards }: { cards: Card[] }) {
  return (
    <section className="mt-6 rounded-3xl border border-white/10 bg-[#0b1734] px-8 py-7 shadow-2xl">
      <div className="text-lg font-black tracking-tight text-amber-300">Risk Breakdown</div>
      <div className="mt-1 h-px w-full bg-amber-300/30" />

      <div className="mt-5 grid gap-4 sm:grid-cols-3">
        {cards.map((c) => {
          const tone = TONES[c.tone];
          return (
            <div
              key={c.label}
              className={`rounded-2xl border ${tone.border} ${tone.bg} p-5 shadow-xl`}
            >
              <div className={`text-[11px] font-black uppercase tracking-[0.25em] ${tone.fg}`}>
                {c.label}
              </div>
              <div className={`mt-2 text-5xl font-black leading-none ${tone.fg}`}>
                {c.count.toLocaleString()}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

