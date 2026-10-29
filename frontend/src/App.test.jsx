import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import App from "./App";
import { apiRequest } from "./api";

vi.mock("./api", () => ({ apiRequest: vi.fn() }));

const demoResources = [
  { id: 1, provider: "aws", name: "production-api-demo", resource_type: "compute", region: "us-east-1", status: "running", simulated: true, metrics: {} },
  { id: 2, provider: "aws", name: "assets-bucket-demo", resource_type: "storage", region: "us-east-1", status: "active", simulated: true, metrics: {} },
];

function mockDashboard(connections = [{ id: 1, provider: "aws", display_name: "Demo", region: "us-east-1", status: "connected", simulated: true }]) {
  apiRequest.mockImplementation((path) => {
    if (path === "/auth/me") return Promise.resolve({ full_name: "Test User", email: "test@example.com" });
    if (path === "/dashboard/summary") return Promise.resolve({ total_resources: 2, active_connections: 1, open_findings: 0, unread_alerts: 0 });
    if (path === "/resources") return Promise.resolve(demoResources);
    if (path === "/connections") return Promise.resolve(connections);
    if (path === "/alerts") return Promise.resolve([]);
    if (path === "/security/findings") return Promise.resolve([]);
    if (path.endsWith("/costs")) return Promise.resolve({ total: 162, currency: "USD", estimated: true, simulated: path.includes("/1/"), period_start: "2026-10-01", period_end: "2026-10-27", services: [] });
    if (path.endsWith("/sync")) return Promise.resolve({ simulated: false, resource_count: 1, synchronized_at: "2026-10-29T12:00:00Z", warnings: [] });
    return Promise.resolve({});
  });
}

describe("CloudBridge dashboard", () => {
  afterEach(() => {
    cleanup();
    localStorage.clear();
  });

  beforeEach(() => {
    localStorage.setItem("cloudbridge_token", "test-token");
    mockDashboard();
  });

  it("filters inventory and shows missing metrics as unavailable", async () => {
    render(<App />);
    await screen.findByText("Good to have you here, Test.");
    fireEvent.click(screen.getByRole("button", { name: "Resources" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search resources" }), { target: { value: "assets" } });
    expect(screen.getByText("assets-bucket-demo")).toBeInTheDocument();
    expect(screen.queryByText("production-api-demo")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Monitoring" }));
    expect(await screen.findAllByText("Unavailable")).toHaveLength(4);
  });

  it("creates a live AWS connection without sending credentials to the browser API", async () => {
    render(<App />);
    await screen.findByText("Good to have you here, Test.");
    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Connections" }));
    fireEvent.click(screen.getByRole("button", { name: "Add connection" }));
    fireEvent.change(screen.getByLabelText("Connection mode"), { target: { value: "live" } });
    fireEvent.change(screen.getByLabelText("Connection name"), { target: { value: "Read-only AWS" } });
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await waitFor(() => expect(apiRequest).toHaveBeenCalledWith(
      "/connections/aws",
      expect.objectContaining({ method: "POST", token: "test-token" }),
    ));
    const request = apiRequest.mock.calls.find(([path]) => path === "/connections/aws")[1];
    expect(request.body).not.toMatch(/access_key|secret_key|session_token/i);
  });

  it("uses the selected live AWS connection instead of a demo connection", async () => {
    mockDashboard([
      { id: 1, provider: "aws", display_name: "Demo", region: "us-east-1", status: "connected", simulated: true },
      { id: 2, provider: "aws", display_name: "Live AWS", region: "us-west-2", status: "connected", simulated: false },
    ]);

    render(<App />);
    await screen.findByText("Good to have you here, Test.");
    await waitFor(() => expect(apiRequest).toHaveBeenCalledWith(
      "/connections/2/costs",
      expect.objectContaining({ token: "test-token" }),
    ));

    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Connections" }));
    const liveConnection = screen.getByRole("heading", { name: "Live AWS" }).closest("article");
    fireEvent.click(within(liveConnection).getByRole("button", { name: "Refresh resources" }));

    await waitFor(() => expect(apiRequest).toHaveBeenCalledWith(
      "/connections/2/sync",
      expect.objectContaining({ method: "POST", token: "test-token" }),
    ));
  });
});
