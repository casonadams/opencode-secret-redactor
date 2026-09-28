import { describe, expect, it, vi } from "vitest";
import { SecretRedactorRpc } from "./rpc.js";
import { SecretRedactorTui } from "./tui.js";

type Handler = (event: { data: Record<string, unknown> }) => void;

function createMockContext() {
  let handler: Handler | undefined;
  const unsubscribe = vi.fn();
  const on = vi.fn((_name: string, callback: Handler) => {
    handler = callback;
    return unsubscribe;
  });
  const rpc = vi.fn(() => ({ events: { on } }));
  const show = vi.fn();
  const context = { client: { rpc }, ui: { toast: { show } } };
  const fire = (data: Record<string, unknown>) => handler?.({ data });
  return { context, rpc, on, show, unsubscribe, fire };
}

describe("SecretRedactorTui plugin", () => {
  it("subscribes to redacted events and returns the unsubscribe cleanup", async () => {
    const { context, rpc, on, unsubscribe } = createMockContext();
    const cleanup = await SecretRedactorTui.setup(context as never);

    expect(rpc).toHaveBeenCalledWith(SecretRedactorRpc);
    expect(on).toHaveBeenCalledWith("redacted", expect.any(Function));
    expect(cleanup).toBe(unsubscribe);
  });

  it("shows a warning toast for each redacted event", async () => {
    const { context, show, fire } = createMockContext();
    await SecretRedactorTui.setup(context as never);

    fire({ message: "Redacted 1 secret(s) from shell: jwt", sessionID: "ses_1" });

    expect(show).toHaveBeenCalledWith({
      title: "Secret redactor",
      message: "Redacted 1 secret(s) from shell: jwt",
      variant: "warning",
      sessionID: "ses_1",
    });
  });

  it("ignores malformed events", async () => {
    const { context, show, fire } = createMockContext();
    await SecretRedactorTui.setup(context as never);

    fire({ count: 1 });

    expect(show).not.toHaveBeenCalled();
  });

  it("does nothing on hosts without plugin RPC", async () => {
    const show = vi.fn();
    const cleanup = await SecretRedactorTui.setup({ client: {}, ui: { toast: { show } } } as never);

    expect(cleanup).toBeUndefined();
  });
});
