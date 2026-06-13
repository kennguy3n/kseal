import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRouterTransport, type ConnectRouter } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import { ListAppsResponseSchema } from "../gen/kseal/v1/registry_pb";
import {
  GetKillSwitchStateResponseSchema,
  KillSwitchService,
  KillSwitchStateSchema,
  KillSwitchStatus,
  RequestKillSwitchChangeResponseSchema,
} from "../gen-local/kseal/consolelocal/v1/compliance_pb";
import { KillSwitchPage } from "./KillSwitch";
import { renderWithProviders } from "../test/render";

function withApps(router: ConnectRouter) {
  router.service(RegistryService, {
    listApps: () =>
      create(ListAppsResponseSchema, {
        apps: [{ id: "app-9", name: "App Nine" }],
      }),
  });
}

function state(status: KillSwitchStatus) {
  return create(KillSwitchStateSchema, {
    status,
    lastChangedBy: "ops@kseal",
    lastChangedAt: 1_700_000_000_000n,
    signingKeyId: "ks-key-1",
    reason: "baseline",
  });
}

describe("KillSwitchPage", () => {
  it("renders the armed state", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(KillSwitchService, {
        getKillSwitchState: () =>
          create(GetKillSwitchStateResponseSchema, {
            state: state(KillSwitchStatus.ARMED),
          }),
      });
    });

    renderWithProviders(<KillSwitchPage />, {
      transport,
      route: "/kill-switch",
    });

    await waitFor(() =>
      expect(screen.getByText("Armed")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/protection is enforcing normally/i),
    ).toBeInTheDocument();
    // From armed, the offered action is to disable.
    expect(
      screen.getByRole("button", { name: /disable enforcement/i }),
    ).toBeInTheDocument();
  });

  it("requires a reason and requests a signed change", async () => {
    const user = userEvent.setup();
    const requests: { appId: string; status: KillSwitchStatus; reason: string }[] =
      [];
    let current = KillSwitchStatus.ARMED;

    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(KillSwitchService, {
        getKillSwitchState: () =>
          create(GetKillSwitchStateResponseSchema, { state: state(current) }),
        requestKillSwitchChange(req) {
          requests.push({
            appId: req.appId,
            status: req.desiredStatus,
            reason: req.reason,
          });
          current = req.desiredStatus;
          return create(RequestKillSwitchChangeResponseSchema, {
            state: state(current),
            signedChangeRef: "ref-1",
          });
        },
      });
    });

    renderWithProviders(<KillSwitchPage />, {
      transport,
      route: "/kill-switch",
    });

    await waitFor(() => expect(screen.getByText("Armed")).toBeInTheDocument());

    // Scope the change to a specific app so we can assert appId travels with
    // the mutation (not captured from a stale closure).
    await user.selectOptions(screen.getByLabelText("App"), "app-9");

    await user.click(
      screen.getByRole("button", { name: /disable enforcement…/i }),
    );

    // Confirm is disabled until a reason is entered.
    const confirm = screen.getByRole("button", { name: /^Confirm:/i });
    expect(confirm).toBeDisabled();

    await user.type(
      screen.getByLabelText(/reason/i),
      "INC-1234 false positive",
    );
    expect(confirm).toBeEnabled();
    await user.click(confirm);

    await waitFor(() => expect(requests).toHaveLength(1));
    expect(requests[0]).toEqual({
      appId: "app-9",
      status: KillSwitchStatus.DISABLED,
      reason: "INC-1234 false positive",
    });
    // After the change the state refetches to DISABLED.
    await waitFor(() =>
      expect(screen.getByText("Disabled")).toBeInTheDocument(),
    );
  });

  it("degrades gracefully when the RPC is not deployed", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
    });

    renderWithProviders(<KillSwitchPage />, {
      transport,
      route: "/kill-switch",
    });

    await waitFor(() =>
      expect(
        screen.getByText(/kill switch is not available yet/i),
      ).toBeInTheDocument(),
    );
  });
});
