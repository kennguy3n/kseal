import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../state/useAuth";

interface NavItem {
  to: string;
  label: string;
  end?: boolean;
}

const navSections: { heading?: string; items: NavItem[] }[] = [
  {
    items: [
      { to: "/", label: "Dashboard", end: true },
      { to: "/apps", label: "Apps" },
      { to: "/policies", label: "Policies" },
      { to: "/events", label: "Events" },
    ],
  },
  {
    heading: "Compliance",
    items: [
      { to: "/audit", label: "Audit trail" },
      { to: "/data-processing", label: "Data processing" },
      { to: "/masvs", label: "MASVS evidence" },
    ],
  },
  {
    heading: "Operations",
    items: [
      { to: "/kill-switch", label: "Kill switch" },
      { to: "/canary", label: "Canary monitor" },
      { to: "/webhooks", label: "Webhooks" },
      { to: "/siem", label: "SIEM" },
    ],
  },
];

export function Layout() {
  const { session, logout } = useAuth();
  const navigate = useNavigate();

  function onLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="flex min-h-full">
      <aside className="sticky top-0 flex h-screen w-56 shrink-0 flex-col overflow-y-auto border-r border-slate-800 bg-panel/60 p-4">
        <div className="mb-6 px-2">
          <div className="text-lg font-semibold text-slate-50">kseal</div>
          <div className="text-xs text-slate-500">console</div>
        </div>
        <nav className="flex flex-col gap-4" aria-label="Primary">
          {navSections.map((section, i) => (
            <div key={section.heading ?? i} className="flex flex-col gap-1">
              {section.heading && (
                <div className="px-3 pb-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  {section.heading}
                </div>
              )}
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `rounded-lg px-3 py-2 text-sm font-medium ${
                      isActive
                        ? "bg-indigo-500/15 text-indigo-200"
                        : "text-slate-300 hover:bg-slate-800"
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="mt-auto space-y-2 px-2 pt-4 text-xs text-slate-500">
          <div>
            <div className="uppercase tracking-wide">Tenant</div>
            <div
              className="truncate font-mono text-slate-300"
              title={session?.tenantId}
            >
              {session?.tenantId}
            </div>
          </div>
          <button className="btn-ghost w-full" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
