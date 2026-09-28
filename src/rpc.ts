import type { Rpc } from "@opencode/plugin/rpc";

// Server plugins in OpenCode 2 cannot show toasts, so the server emits this
// event and the TUI plugin (`./tui`) turns it into a toast.
export const SecretRedactorRpc = {
  id: "secret-redactor",
  methods: {},
  events: {
    redacted: {
      schema: {
        type: "object",
        properties: {
          message: { type: "string" },
          sessionID: { type: "string" },
        },
        required: ["message"],
        additionalProperties: false,
      },
    },
  },
} as const satisfies Rpc.PortableDefinition;

export interface RedactedEvent {
  readonly message: string;
  readonly sessionID?: string;
}
