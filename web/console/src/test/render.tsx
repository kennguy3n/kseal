import type { ReactElement, ReactNode } from "react";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { Transport } from "@connectrpc/connect";
import { AuthProvider } from "../state/AuthContext";

export const TEST_SESSION = {
  apiBaseUrl: "http://test.local",
  tenantId: "tenant-test",
  apiKey: "ksk_test",
};

// Seeds an authenticated session in localStorage and wraps the tree with the
// app providers, injecting an in-memory transport so no network is hit.
export function renderWithProviders(
  ui: ReactElement,
  options: { transport: Transport; route?: string },
) {
  localStorage.setItem(
    "kseal.console.session.v1",
    JSON.stringify(TEST_SESSION),
  );
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <AuthProvider transport={options.transport}>
          <MemoryRouter initialEntries={[options.route ?? "/"]}>
            {children}
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );
  }

  return render(ui, { wrapper: Wrapper });
}
