import type { Plugin as OpencodePlugin } from "@opencode/plugin";
import type { RedactResult } from "./redactor.js";
import type { SecretVault } from "./vault.js";

type RedactDeep = (value: unknown, vault: SecretVault) => RedactResult;

// Structural views of the model-request and tool-result shapes the hooks
// receive. Structural (rather than imported) so the plugin carries no runtime
// dependency on @opencode/plugin.
interface RedactablePart {
  type: string;
  text?: string;
  input?: unknown;
  result?: { value?: unknown };
}

interface RedactableMessage {
  content?: ReadonlyArray<RedactablePart>;
}

interface RedactableSystemPart {
  text?: string;
}

interface RedactableRequest {
  messages: ReadonlyArray<RedactableMessage>;
  system: ReadonlyArray<RedactableSystemPart>;
}

interface RedactableToolResult {
  output?: unknown;
  content?: string | ReadonlyArray<RedactablePart>;
  metadata?: unknown;
}

function isToolInScope(tool: string, tools: ReadonlyArray<string>): boolean {
  return tools.includes(tool);
}

function redactInto(
  value: unknown,
  redactDeep: RedactDeep,
  vault: SecretVault,
  labels: string[],
): unknown {
  const result = redactDeep(value, vault);
  labels.push(...result.labels);
  return result.value;
}

function redactMessage(
  message: RedactableMessage,
  redactDeep: RedactDeep,
  vault: SecretVault,
  labels: string[],
): void {
  if (!Array.isArray(message.content)) return;
  for (const part of message.content) {
    if ((part.type === "text" || part.type === "reasoning") && typeof part.text === "string") {
      part.text = redactInto(part.text, redactDeep, vault, labels) as string;
    } else if (part.type === "tool-call" && part.input !== undefined) {
      part.input = redactInto(part.input, redactDeep, vault, labels);
    } else if (part.type === "tool-result" && part.result) {
      part.result.value = redactInto(part.result.value, redactDeep, vault, labels);
    }
  }
}

// Redacts every model-visible string in an assembled request: text and
// reasoning parts, tool-call inputs, tool results, and system instructions.
function redactRequest(event: RedactableRequest, redactDeep: RedactDeep, vault: SecretVault): void {
  const labels: string[] = [];
  for (const message of event.messages) redactMessage(message, redactDeep, vault, labels);
  for (const part of event.system) {
    if (typeof part.text === "string") {
      part.text = redactInto(part.text, redactDeep, vault, labels) as string;
    }
  }
}

function redactToolResult(
  result: RedactableToolResult,
  redactDeep: RedactDeep,
  vault: SecretVault,
  labels: string[],
): RedactableToolResult {
  if (result.output !== undefined) {
    result.output = redactInto(result.output, redactDeep, vault, labels);
  }
  if (typeof result.content === "string") {
    result.content = redactInto(result.content, redactDeep, vault, labels) as string;
  } else if (Array.isArray(result.content)) {
    result.content = result.content.map((part) =>
      part.type === "text" && typeof part.text === "string"
        ? { ...part, text: redactInto(part.text, redactDeep, vault, labels) as string }
        : part,
    );
  }
  return result;
}

// OpenCode v2 plugin: a default export with a stable `id` and a `setup(ctx)`
// that registers hooks on the domains that own each operation.
export const SecretRedactor: OpencodePlugin.Plugin = {
  id: "opencode-secret-redactor",
  async setup(ctx) {
    const [
      { REDACT_OUTPUT_TOOLS, UNREDACT_ARGS_TOOLS, configure, loadConfig },
      { redactDeep, unredactDeep },
      { createVault },
    ] = await Promise.all([import("./config.js"), import("./redactor.js"), import("./vault.js")]);

    configure(loadConfig(ctx.location.directory));
    const vault = createVault();

    // User prompt text is persisted, so redact at admission.
    await ctx.session.hook("prompt", (event) => {
      const result = redactDeep(event.prompt.text, vault);
      event.prompt.text = result.value as string;
    });

    // Redact everything a model request can carry. Register each kind so
    // auxiliary requests (compaction, titles, transient generation) are covered
    // too, not just the agent loop.
    const redactRequestHook = (event: unknown) => {
      redactRequest(event as RedactableRequest, redactDeep, vault);
    };
    await ctx.session.hook("context", redactRequestHook);
    await ctx.session.hook("compaction", redactRequestHook);
    await ctx.session.hook("generate", redactRequestHook);
    await ctx.session.hook("title", redactRequestHook);

    // Restore real values in tool arguments before execution.
    await ctx.tool.hook("execute.before", (event) => {
      if (!isToolInScope(event.tool, UNREDACT_ARGS_TOOLS)) return;
      event.input = unredactDeep(event.input, vault);
    });

    // Redact tool output before it enters context.
    await ctx.tool.hook("execute.after", (event) => {
      if (event.status !== "completed") return;
      if (!isToolInScope(event.tool, REDACT_OUTPUT_TOOLS)) return;

      const labels: string[] = [];
      const result = event.result as unknown as RedactableToolResult;
      const next = redactToolResult({ ...result }, redactDeep, vault, labels);
      if (labels.length > 0) event.result = next as unknown as typeof event.result;
    });
  },
};

export default SecretRedactor;
