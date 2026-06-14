import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { SeverityBar } from "./SeverityBar";

describe("SeverityBar", () => {
  const segments = [
    { key: "a", label: "Healthy", value: 3, color: "rgb(16 185 129)" },
    { key: "b", label: "At risk", value: 1, color: "rgb(244 63 94)" },
    { key: "c", label: "Unknown", value: 0, color: "rgb(100 116 139)" },
  ];

  it("summarizes non-zero segments in the accessible label", () => {
    render(<SeverityBar segments={segments} ariaLabel="Health" />);
    expect(screen.getByRole("img", { name: "Health: Healthy 3, At risk 1" })).toBeInTheDocument();
  });

  it("renders a legend entry with the count for every segment", () => {
    render(<SeverityBar segments={segments} ariaLabel="Health" />);
    const healthy = screen.getByText("Healthy").closest("li");
    expect(within(healthy as HTMLElement).getByText("3")).toBeInTheDocument();
    // Zero-value segments still appear in the legend for completeness.
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("reports no data for an all-zero distribution", () => {
    render(
      <SeverityBar
        segments={[{ key: "x", label: "X", value: 0, color: "red" }]}
        ariaLabel="Empty"
      />,
    );
    expect(screen.getByRole("img", { name: "Empty: no data" })).toBeInTheDocument();
  });
});
