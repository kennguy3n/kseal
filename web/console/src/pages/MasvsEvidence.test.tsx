import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import {
  AppSchema,
  BuildSchema,
  ListAppsResponseSchema,
  ListBuildsResponseSchema,
} from "../gen/kseal/v1/registry_pb";
import { MasvsEvidencePage } from "./MasvsEvidence";
import { renderWithProviders } from "../test/render";

describe("MasvsEvidencePage", () => {
  it("renders MASVS coverage derived from the selected build manifest", async () => {
    const user = userEvent.setup();
    const transport = createRouterTransport(({ service }) => {
      service(RegistryService, {
        listApps: () =>
          create(ListAppsResponseSchema, {
            apps: [create(AppSchema, { id: "app-1", name: "Acme Wallet" })],
          }),
        listBuilds: () =>
          create(ListBuildsResponseSchema, {
            builds: [
              create(BuildSchema, {
                id: "build-1",
                appId: "app-1",
                buildHash: "deadbeefcafef00d1122",
                versionName: "4.2.0",
                versionCode: 420n,
                createdAt: 1_700_000_000_000n,
                manifest: JSON.stringify({
                  modules: ["root", "attestation", "crypto"],
                  transforms: ["string-obfuscation"],
                }),
              }),
            ],
          }),
      });
    });

    renderWithProviders(<MasvsEvidencePage />, {
      transport,
      route: "/masvs",
    });

    // Initially prompts to select an app.
    expect(
      screen.getByText(/select an app to view its masvs evidence/i),
    ).toBeInTheDocument();

    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "Acme Wallet" }),
      ).toBeInTheDocument(),
    );
    await user.selectOptions(screen.getByLabelText("App"), "app-1");

    // Coverage summary: root -> PLATFORM/RESILIENCE, attestation -> AUTH/NETWORK,
    // crypto -> CRYPTO => 5/8.
    await waitFor(() => expect(screen.getByText("5/8")).toBeInTheDocument());
    expect(screen.getByText("MASVS-CRYPTO")).toBeInTheDocument();
    expect(screen.getAllByText("Evidenced").length).toBeGreaterThan(0);
    // The build proof hash is surfaced.
    expect(screen.getByText("deadbeefcafef00d1122")).toBeInTheDocument();
    // The applied transform is listed.
    expect(screen.getByText("string-obfuscation")).toBeInTheDocument();
  });

  it("shows an empty state for an app with no builds", async () => {
    const user = userEvent.setup();
    const transport = createRouterTransport(({ service }) => {
      service(RegistryService, {
        listApps: () =>
          create(ListAppsResponseSchema, {
            apps: [create(AppSchema, { id: "app-1", name: "Acme Wallet" })],
          }),
        listBuilds: () => create(ListBuildsResponseSchema, {}),
      });
    });

    renderWithProviders(<MasvsEvidencePage />, {
      transport,
      route: "/masvs",
    });

    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "Acme Wallet" }),
      ).toBeInTheDocument(),
    );
    await user.selectOptions(screen.getByLabelText("App"), "app-1");

    await waitFor(() =>
      expect(
        screen.getByText(/no builds registered for this app yet/i),
      ).toBeInTheDocument(),
    );
  });
});
