import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./state/useAuth";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/Login";
import { DashboardPage } from "./pages/Dashboard";
import { Spinner } from "./components/ui";

// The dashboard (landing) and login stay in the main chunk for an instant
// first paint. Every other view is code-split and loaded on demand to keep the
// initial bundle small. Pages use named exports, so map them to `default`.
const AppsListPage = lazy(() =>
  import("./pages/AppsList").then((m) => ({ default: m.AppsListPage })),
);
const AppDetailPage = lazy(() =>
  import("./pages/AppDetail").then((m) => ({ default: m.AppDetailPage })),
);
const PolicyEditorPage = lazy(() =>
  import("./pages/PolicyEditor").then((m) => ({ default: m.PolicyEditorPage })),
);
const EventsPage = lazy(() =>
  import("./pages/Events").then((m) => ({ default: m.EventsPage })),
);
const WebhooksPage = lazy(() =>
  import("./pages/Webhooks").then((m) => ({ default: m.WebhooksPage })),
);
const SiemConnectorsPage = lazy(() =>
  import("./pages/SiemConnectors").then((m) => ({
    default: m.SiemConnectorsPage,
  })),
);
const AuditTrailPage = lazy(() =>
  import("./pages/AuditTrail").then((m) => ({ default: m.AuditTrailPage })),
);
const DataProcessingPage = lazy(() =>
  import("./pages/DataProcessing").then((m) => ({
    default: m.DataProcessingPage,
  })),
);
const MasvsEvidencePage = lazy(() =>
  import("./pages/MasvsEvidence").then((m) => ({
    default: m.MasvsEvidencePage,
  })),
);
const KillSwitchPage = lazy(() =>
  import("./pages/KillSwitch").then((m) => ({ default: m.KillSwitchPage })),
);
const CanaryPage = lazy(() =>
  import("./pages/Canary").then((m) => ({ default: m.CanaryPage })),
);

function RequireAuth({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const location = useLocation();
  if (!session) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

// Shown while a lazily-loaded route chunk is being fetched.
function RouteFallback() {
  return (
    <div className="p-2">
      <Spinner label="Loading…" />
    </div>
  );
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
        <Route
          path="apps"
          element={
            <Suspense fallback={<RouteFallback />}>
              <AppsListPage />
            </Suspense>
          }
        />
        <Route
          path="apps/:appId"
          element={
            <Suspense fallback={<RouteFallback />}>
              <AppDetailPage />
            </Suspense>
          }
        />
        <Route
          path="policies"
          element={
            <Suspense fallback={<RouteFallback />}>
              <PolicyEditorPage />
            </Suspense>
          }
        />
        <Route
          path="events"
          element={
            <Suspense fallback={<RouteFallback />}>
              <EventsPage />
            </Suspense>
          }
        />
        <Route
          path="webhooks"
          element={
            <Suspense fallback={<RouteFallback />}>
              <WebhooksPage />
            </Suspense>
          }
        />
        <Route
          path="siem"
          element={
            <Suspense fallback={<RouteFallback />}>
              <SiemConnectorsPage />
            </Suspense>
          }
        />
        <Route
          path="audit"
          element={
            <Suspense fallback={<RouteFallback />}>
              <AuditTrailPage />
            </Suspense>
          }
        />
        <Route
          path="data-processing"
          element={
            <Suspense fallback={<RouteFallback />}>
              <DataProcessingPage />
            </Suspense>
          }
        />
        <Route
          path="masvs"
          element={
            <Suspense fallback={<RouteFallback />}>
              <MasvsEvidencePage />
            </Suspense>
          }
        />
        <Route
          path="kill-switch"
          element={
            <Suspense fallback={<RouteFallback />}>
              <KillSwitchPage />
            </Suspense>
          }
        />
        <Route
          path="canary"
          element={
            <Suspense fallback={<RouteFallback />}>
              <CanaryPage />
            </Suspense>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
