import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../state/useAuth";

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/apps", label: "Apps", end: false },
  { to: "/policies", label: "Policies", end: false },
  { to: "/events", label: "Events", end: false },
  { to: "/webhooks", label: "Webhooks", end: false },
  { to: "/siem", label: "SIEM", end: false },
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
      <aside className="flex w-56 flex-col border-r border-slate-800 bg-panel/60 p-4">
        <div className="mb-6 px-2">
          <div className="text-lg font-semibold text-slate-50">kseal</div>
          <div className="text-xs text-slate-500">console</div>
        </div>
        <nav className="flex flex-col gap-1">
          {navItems.map((item) => (
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
