import type { Plugin } from "@opencode/plugin/tui";
import { type RedactedEvent, SecretRedactorRpc } from "./rpc.js";

// Shows a toast for each redaction reported by the OpenCode 2 server plugin
export const SecretRedactorTui: Plugin.Definition = {
  id: "secret-redactor.tui",
  setup(context) {
    // OpenCode 1 TUIs have neither plugin RPC nor this toast API
    if (typeof context.client?.rpc !== "function" || !context.ui?.toast) return;

    return context.client.rpc(SecretRedactorRpc).events.on("redacted", (event) => {
      const { message, sessionID } = event.data as Partial<RedactedEvent>;
      if (typeof message !== "string") return;
      context.ui.toast.show({
        title: "Secret redactor",
        message,
        variant: "warning",
        sessionID: typeof sessionID === "string" ? sessionID : undefined,
      });
    });
  },
};

export default SecretRedactorTui;
