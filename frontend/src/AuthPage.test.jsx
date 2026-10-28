import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuthPage } from "./AuthPage";

describe("AuthPage", () => {
  it("shows a sign-in form and switches to validated registration", () => {
    render(<AuthPage onAuthenticated={vi.fn()} />);
    expect(screen.getByRole("heading", { name: "Sign in to CloudBridge." })).toBeInTheDocument();
    expect(screen.getByLabelText("Work email")).toHaveAttribute("type", "email");

    fireEvent.click(screen.getByRole("button", { name: "Create an account" }));
    expect(screen.getByRole("heading", { name: "Start with a clear view." })).toBeInTheDocument();
    expect(screen.getByLabelText("Full name")).toBeRequired();
    expect(screen.getByLabelText("Password")).toHaveAttribute("minLength", "12");
  });
});
