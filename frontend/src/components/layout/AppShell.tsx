import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";
import { useAuth } from "@/context/AuthContext";
import Logo from "@/components/brand/Logo";

const SECTIONS: { title: string; items: { to: string; label: string; icon: string }[] }[] = [
  {
    title: "Core",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: "◉" },
      { to: "/cves", label: "CVE Explorer", icon: "⌬" },
      { to: "/kev", label: "CISA KEV", icon: "⚡" },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { to: "/threat-map", label: "Threat Map", icon: "◎" },
      { to: "/attack-surface", label: "Attack Surface", icon: "⊙" },
      { to: "/news", label: "News Feed", icon: "✦" },
    ],
  },
  {
    title: "Organisation",
    items: [
      { to: "/profiles", label: "Org Profiles", icon: "▣" },
      { to: "/asset-health", label: "Asset Health", icon: "❇" },
      { to: "/compliance", label: "Compliance Radar", icon: "⎈" },
      { to: "/policies", label: "Policy Recs", icon: "⎆" },
      { to: "/reports", label: "Reports", icon: "⎙" },
      { to: "/account", label: "Account", icon: "⚙" },
    ],
  },
  {
    title: "AI",
    items: [{ to: "/assistant", label: "AI Assistant", icon: "✧" }],
  },
];

export default function AppShell() {
  const { user, isGuest, logout } = useAuth();

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-64 shrink-0 flex-col border-r border-sentinel-border bg-white">
        <div className="border-b border-sentinel-border px-5 py-5">
          <Logo tagline />
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4">
          {SECTIONS.map((section) => (
            <div key={section.title} className="side-section">
              <div className="side-heading">{section.title}</div>
              <div className="space-y-1">
                {section.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      clsx("side-item", isActive && "side-item--active")
                    }
                  >
                    <span className="text-base leading-none opacity-80">{item.icon}</span>
                    <span>{item.label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-sentinel-border p-4 text-xs text-slate-500">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0 flex-1">
              <div className="truncate font-semibold text-sentinel-ink">
                {user?.username || (isGuest ? "Guest" : "—")}
              </div>
              <div className="mt-0.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                {user?.role || (isGuest ? "guest" : "")}
              </div>
            </div>
            <button onClick={logout} className="btn-secondary !px-3 !py-1 text-xs">
              Sign out
            </button>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <main className="flex-1 px-8 py-8">
          <Outlet />
        </main>
        <footer className="border-t border-sentinel-border bg-white px-8 py-3 text-right text-[11px] text-slate-500">
          SentinelIX · NVD + CISA KEV + Shodan + News correlation
        </footer>
      </div>
    </div>
  );
}
