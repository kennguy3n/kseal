import { useEffect, useRef, useState } from "react";
import {
  NavLink,
  Outlet,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { useAuth } from "../state/useAuth";
import { useTheme } from "../lib/theme";
import { CloseIcon, MenuIcon, MoonIcon, ShieldIcon, SunIcon } from "./icons";

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

function ThemeToggle({ className = "" }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";
  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
      title={isDark ? "Switch to light theme" : "Switch to dark theme"}
      className={`inline-flex h-9 w-9 items-center justify-center rounded-lg border border-line-strong text-fg hover:bg-elevated ${className}`}
    >
      {isDark ? (
        <SunIcon className="h-4 w-4" />
      ) : (
        <MoonIcon className="h-4 w-4" />
      )}
    </button>
  );
}

function NavSections({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <>
      {navSections.map((section, i) => (
        <div key={section.heading ?? i} className="flex flex-col gap-1">
          {section.heading && (
            <div className="px-3 pb-0.5 text-[10px] font-semibold uppercase tracking-wider text-fg-subtle">
              {section.heading}
            </div>
          )}
          {section.items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={onNavigate}
              className={({ isActive }) =>
                `rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? "bg-accent-strong/15 text-accent"
                    : "text-fg hover:bg-elevated"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </div>
      ))}
    </>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-2">
      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent-strong/15 text-accent">
        <ShieldIcon className="h-4 w-4" />
      </span>
      <div>
        <div className="text-lg font-semibold leading-none text-fg-strong">
          kseal
        </div>
        <div className="text-xs text-fg-subtle">console</div>
      </div>
    </div>
  );
}

export function Layout() {
  const { session, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  function onLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  // Close the mobile drawer whenever the route changes (navigation completed).
  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  // While the drawer is open, lock background scroll, move focus into it, and
  // wire Escape to close — basic dialog focus management.
  useEffect(() => {
    if (!mobileOpen) return;
    closeButtonRef.current?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setMobileOpen(false);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [mobileOpen]);

  return (
    <div className="flex min-h-full">
      {/* Keyboard skip link: first tab stop, jumps past the nav to content. */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-accent-strong focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-white"
      >
        Skip to main content
      </a>

      {/* Persistent sidebar (tablet and up). */}
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col overflow-y-auto border-r border-line bg-surface/60 p-4 lg:flex">
        <div className="mb-6 px-1">
          <Brand />
        </div>
        <nav className="flex flex-col gap-4" aria-label="Primary">
          <NavSections />
        </nav>
        <div className="mt-auto space-y-3 px-1 pt-4 text-xs text-fg-subtle">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="uppercase tracking-wide">Tenant</div>
              <div
                className="truncate font-mono text-fg"
                title={session?.tenantId}
              >
                {session?.tenantId}
              </div>
            </div>
            <ThemeToggle />
          </div>
          <button className="btn-ghost w-full" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </aside>

      {/* Mobile top bar (below the lg breakpoint). */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center justify-between gap-2 border-b border-line bg-surface/80 px-4 py-3 backdrop-blur lg:hidden">
          <Brand />
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation menu"
              aria-expanded={mobileOpen}
              aria-controls="mobile-nav"
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-line-strong text-fg hover:bg-elevated"
            >
              <MenuIcon className="h-5 w-5" />
            </button>
          </div>
        </header>

        {mobileOpen && (
          <div className="fixed inset-0 z-40 lg:hidden">
            <div
              className="absolute inset-0 bg-black/50"
              onClick={() => setMobileOpen(false)}
              aria-hidden="true"
            />
            <div
              id="mobile-nav"
              role="dialog"
              aria-modal="true"
              aria-label="Navigation"
              className="absolute left-0 top-0 flex h-full w-72 max-w-[85%] flex-col overflow-y-auto border-r border-line bg-surface p-4"
            >
              <div className="mb-6 flex items-center justify-between">
                <Brand />
                <button
                  ref={closeButtonRef}
                  type="button"
                  onClick={() => setMobileOpen(false)}
                  aria-label="Close navigation menu"
                  className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-line-strong text-fg hover:bg-elevated"
                >
                  <CloseIcon className="h-5 w-5" />
                </button>
              </div>
              <nav className="flex flex-col gap-4" aria-label="Primary">
                <NavSections onNavigate={() => setMobileOpen(false)} />
              </nav>
              <div className="mt-auto space-y-2 pt-4 text-xs text-fg-subtle">
                <div>
                  <div className="uppercase tracking-wide">Tenant</div>
                  <div className="truncate font-mono text-fg">
                    {session?.tenantId}
                  </div>
                </div>
                <button className="btn-ghost w-full" onClick={onLogout}>
                  Sign out
                </button>
              </div>
            </div>
          </div>
        )}

        <main id="main-content" tabIndex={-1} className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-6xl p-4 sm:p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
