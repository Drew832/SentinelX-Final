import type { ReactNode } from "react";

export default function ReportSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="relative mt-6 rounded-3xl border border-white/10 bg-[#0b1734] px-8 py-7 shadow-2xl">
      <div className="text-lg font-black tracking-tight text-amber-300">{title}</div>
      <div className="mt-1 h-px w-full bg-amber-300/30" />
      <div className="mt-4 text-sm leading-relaxed text-slate-100">{children}</div>
    </section>
  );
}

