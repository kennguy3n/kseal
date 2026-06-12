import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "./state/useAuth";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/Login";
import { DashboardPage } from "./pages/Dashboard";
import { AppsListPage } from "./pages/AppsList";
import { AppDetailPage } from "./pages/AppDetail";
import { PolicyEditorPage } from "./pages/PolicyEditor";
import { EventsPage } from "./pages/Events";
import { WebhooksPage } from "./pages/Webhooks";

function RequireAuth({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const location = useLocation();
  if (!session) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="apps" element={<AppsListPage />} />
        <Route path="apps/:appId" element={<AppDetailPage />} />
        <Route path="policies" element={<PolicyEditorPage />} />
        <Route path="events" element={<EventsPage />} />
        <Route path="webhooks" element={<WebhooksPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
