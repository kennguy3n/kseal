import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import {
  CreatePolicyResponseSchema,
  ListAppsResponseSchema,
  ListPoliciesResponseSchema,
  PolicySchema,
  type CreatePolicyRequest,
} from "../gen/kseal/v1/registry_pb";
import { EnforcementMode } from "../gen/kseal/v1/common_pb";
import { PolicyEditorPage } from "./PolicyEditor";
import { renderWithProviders } from "../test/render";

function makeTransport(onCreate: (req: CreatePolicyRequest) => void) {
  return createRouterTransport(({ service }) => {
    service(RegistryService, {
      listApps: () => create(ListAppsResponseSchema, { apps: [] }),
      listPolicies: () =>
        create(ListPoliciesResponseSchema, { policies: [] }),
      createPolicy(req) {
        onCreate(req);
        return create(CreatePolicyResponseSchema, {
          policy: create(PolicySchema, { id: "p1", name: req.name }),
        });
      },
    });
  });
}

describe("PolicyEditorPage", () => {
  it("submits a parsed policy draft to the server", async () => {
    const user = userEvent.setup();
    let captured: CreatePolicyRequest | null = null;
    renderWithProviders(<PolicyEditorPage />, {
      transport: makeTransport((req) => {
        captured = req;
      }),
      route: "/policies",
    });

    await waitFor(() =>
      expect(
        screen.getByText("No policies yet for this scope."),
      ).toBeInTheDocument(),
    );

    await user.type(screen.getByLabelText("Name"), "Strict");
    await user.selectOptions(
      screen.getByLabelText("Enforcement mode"),
      String(EnforcementMode.BLOCK),
    );
    const modules = screen.getByLabelText("Enabled modules");
    await user.clear(modules);
    await user.type(modules, "root debugger root");

    await user.click(screen.getByRole("button", { name: "Create policy" }));

    await waitFor(() => expect(captured).not.toBeNull());
    const req = captured as unknown as CreatePolicyRequest;
    expect(req.name).toBe("Strict");
    expect(req.enforcementMode).toBe(EnforcementMode.BLOCK);
    expect(req.modulesEnabled).toEqual(["root", "debugger"]);
    expect(JSON.parse(req.riskThresholds)).toEqual({
      MEDIUM_RISK: 40,
      HIGH_RISK: 70,
    });
  });

  it("blocks submission and shows a validation error for invalid JSON", async () => {
    const user = userEvent.setup();
    let createCalls = 0;
    renderWithProviders(<PolicyEditorPage />, {
      transport: makeTransport(() => {
        createCalls += 1;
      }),
      route: "/policies",
    });

    await waitFor(() =>
      expect(
        screen.getByText("No policies yet for this scope."),
      ).toBeInTheDocument(),
    );

    await user.type(screen.getByLabelText("Name"), "Broken");
    const thresholds = screen.getByLabelText("Risk thresholds (JSON)");
    await user.clear(thresholds);
    // `{{` types a literal `{` in user-event's keyboard syntax.
    await user.type(thresholds, "{{not valid");

    await user.click(screen.getByRole("button", { name: "Create policy" }));

    expect(await screen.findByText(/Invalid JSON/)).toBeInTheDocument();
    expect(createCalls).toBe(0);
  });
});
