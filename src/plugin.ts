import type { Plugin } from "@opencode-ai/plugin";
import type { RedactResult } from "./redactor.js";
import type { SecretVault } from "./vault.js";

interface TextPart {
  type: "text";
  text: string;
}

function isTextPart(part: unknown): part is TextPart {
  return typeof part === "object" && part !== null && (part as TextPart).type === "text";
}

function isToolInScope(tool: string, tools: ReadonlyArray<string>): boolean {
  return tools.includes(tool);
}

function uniqueTypes(labels: ReadonlyArray<string>): string[] {
  const types = new Set<string>();
  for (const label of labels) {
    types.add(label.replace(/_\d+$/, ""));
  }
  return Array.from(types);
}

function redactParts(
  parts: Array<{ type: string; text?: string }>,
  redactDeep: (value: unknown, vault: SecretVault) => RedactResult,
  vault: SecretVault,
): string[] {
  const allLabels: string[] = [];
  for (const part of parts) {
    if (!isTextPart(part)) continue;
    const result = redactDeep(part.text, vault);
    part.text = result.value as string;
    allLabels.push(...result.labels);
  }
  return allLabels;
}

// Named export for programmatic consumers
export const SecretRedactor: Plugin = async ({ client }) => {
  const [
    { REDACT_OUTPUT_TOOLS, UNREDACT_ARGS_TOOLS },
    { redactDeep, unredactDeep },
    { createVault },
  ] = await Promise.all([import("./config.js"), import("./redactor.js"), import("./vault.js")]);

  const vault = createVault();

  return {
    "chat.message": async (_input, output) => {
      const allLabels = redactParts(output.parts, redactDeep, vault);

      if (allLabels.length > 0) {
        const types = uniqueTypes(allLabels);
        client.tui
          .showToast({
            body: {
              message: `Redacted ${allLabels.length} secret(s) from chat: ${types.join(", ")}`,
              variant: "warning",
            },
          })
          .catch(() => {});
      }
    },

    "experimental.chat.messages.transform": async (_input, output) => {
      let totalRedacted = 0;
      for (const msg of output.messages) {
        const labels = redactParts(msg.parts, redactDeep, vault);
        totalRedacted += labels.length;
      }

      if (totalRedacted > 0) {
        client.tui
          .showToast({
            body: {
              message: `Redacted ${totalRedacted} secret(s) from LLM context`,
              variant: "warning",
            },
          })
          .catch(() => {});
      }
    },

    "tool.execute.before": async (input, output) => {
      if (!isToolInScope(input.tool, UNREDACT_ARGS_TOOLS)) return;

      for (const key of Object.keys(output.args)) {
        output.args[key] = unredactDeep(output.args[key], vault);
      }
    },

    "tool.execute.after": async (input, output) => {
      if (!isToolInScope(input.tool, REDACT_OUTPUT_TOOLS)) return;
      if (output.output === undefined || output.output === null) return;

      const result = redactDeep(output.output, vault);
      output.output = result.value as string;

      if (result.labels.length > 0) {
        const types = uniqueTypes(result.labels);
        client.tui
          .showToast({
            body: {
              message: `Redacted ${result.labels.length} secret(s) from ${input.tool}: ${types.join(", ")}`,
              variant: "warning",
            },
          })
          .catch(() => {});
      }
    },
  };
};

// OpenCode resolves npm plugins via the default export. The object form
// ({ id, server }) is required: it is picked up by the loader's readV1Plugin
// path and avoids getLegacyPlugins, which throws "Plugin export is not a
// function" on CJS builds that expose non-function exports alongside the
// plugin (see getLegacyPlugins in packages/opencode/src/plugin/index.ts).
export const secretRedactorPlugin = {
  id: "opencode-secret-redactor",
  server: SecretRedactor,
};

export default secretRedactorPlugin;
