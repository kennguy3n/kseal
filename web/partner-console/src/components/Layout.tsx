import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../state/useAuth";
import { ThemeToggle } from "./ThemeToggle";

const navItems = [
  { to: "/", label: "Fleet", end: true },
  { to: "/tenants", label: "Tenants", end: false },
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
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-accent focus:px-3 focus:py-2 focus:text-sm focus:text-accent-fg"
      >
        Skip to content
      </a>
      <aside className="flex w-56 flex-col border-r border-line bg-panel/60 p-4">
        <div className="mb-6 px-2">
          <div className="text-lg font-semibold text-heading">kseal</div>
          <div className="text-xs text-subtle">partner console</div>
        </div>
        <nav aria-label="Primary" className="flex flex-col gap-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `focus-ring rounded-lg px-3 py-2 text-sm font-medium ${
                  isActive
                    ? "bg-accent/15 text-accent-strong"
                    : "text-content hover:bg-hover"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto space-y-3 px-2 pt-4 text-xs text-subtle">
          <div>
            <div className="uppercase tracking-wide">Managed tenants</div>
            <div className="font-mono text-content">
              {session?.tenantIds.length ?? 0}
            </div>
          </div>
          <ThemeToggle />
          <button className="btn-ghost w-full focus-ring" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </aside>
      <main id="main-content" className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
