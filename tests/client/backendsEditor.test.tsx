/**
 * @fileoverview Tests for the gateway backends row editor.
 *
 * The bug these exist for: rows used to be derived from the serialized string
 * on every render. A half-filled row cannot be represented in that string —
 * serializing drops it — so "Add backend" created a row that vanished before
 * it could be rendered, and the button appeared to do nothing.
 */


import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { BackendsEditor } from "../../client/src/components/BackendsEditor";

function renderEditor(value = "") {
  const onChange = vi.fn();
  const utils = render(<BackendsEditor value={value} onChange={onChange} />);
  return { onChange, ...utils };
}

describe("BackendsEditor", () => {
  it("adds a visible row when Add backend is clicked", () => {
    renderEditor("");
    expect(screen.queryByPlaceholderText("Name")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /add backend/i }));

    expect(screen.getByPlaceholderText("Name")).toBeTruthy();
  });

  it("keeps adding rows on repeated clicks", () => {
    renderEditor("");
    const add = screen.getByRole("button", { name: /add backend/i });

    fireEvent.click(add);
    fireEvent.click(add);
    fireEvent.click(add);

    expect(screen.getAllByPlaceholderText("Name")).toHaveLength(3);
  });

  it("keeps a half-filled row on screen", () => {
    // Typing a name before a URL must not make the row disappear.
    renderEditor("");
    fireEvent.click(screen.getByRole("button", { name: /add backend/i }));
    fireEvent.change(screen.getByPlaceholderText("Name"), { target: { value: "App" } });

    expect((screen.getByPlaceholderText("Name") as HTMLInputElement).value).toBe("App");
  });

  it("reports the backend once both fields are filled", () => {
    const { onChange } = renderEditor("");
    fireEvent.click(screen.getByRole("button", { name: /add backend/i }));
    fireEvent.change(screen.getByPlaceholderText("Name"), { target: { value: "App" } });
    fireEvent.change(screen.getByPlaceholderText("ssh://10.0.0.9:22"), {
      target: { value: "http://10.0.0.5:8080" },
    });

    expect(onChange).toHaveBeenLastCalledWith("App=http://10.0.0.5:8080");
  });

  it("shows existing backends as rows", () => {
    renderEditor("App=http://10.0.0.5:8080, Desk=rdp://10.0.0.9:3389;eddsa");

    const names = screen.getAllByPlaceholderText("Name") as HTMLInputElement[];
    expect(names.map((i) => i.value)).toEqual(["App", "Desk"]);
  });

  it("removes a row and reports the remainder", () => {
    const { onChange } = renderEditor("App=http://h:80, Desk=rdp://h:3389");

    // Each row has one delete button; the second row's is the second one.
    const deletes = screen.getAllByRole("button").filter((b) => b.querySelector("svg.lucide-trash2"));
    fireEvent.click(deletes[1]);

    expect(onChange).toHaveBeenLastCalledWith("App=http://h:80");
  });

  it("reports a flag change", () => {
    const { onChange } = renderEditor("Desk=rdp://h:3389");
    fireEvent.click(screen.getByLabelText(/eddsa/i, { selector: "input" }));

    expect(onChange).toHaveBeenLastCalledWith("Desk=rdp://h:3389;eddsa");
  });
});
