import type { Plugin } from "@opencode/plugin";
import { REDACT_OUTPUT_TOOLS, UNREDACT_ARGS_TOOLS } from "./config.js";
import { redactDeep, redactString, unredactDeep } from "./redactor.js";
import { type RedactedEvent, SecretRedactorRpc } from "./rpc.js";
import { isToolInScope, uniqueTypes } from "./util.js";
import { createVault, type SecretVault } from "./vault.js";

interface Mention {
  start: number;
  end: number;
}

export interface PromptDraft {
  text: string;
  files?: Array<{ mention?: Mention }>;
  agents?: Array<{ mention?: Mention }>;
  skills?: Array<{ mention?: Mention }>;
}

// Structural view of `@opencode/ai` messages; only the fields that reach the model.
interface MessageLike {
  readonly content: ReadonlyArray<unknown>;
}

type MutablePart = Record<string, unknown> & { type?: unknown };

/**
 * Redacts the prompt text while keeping file, agent, and skill mentions
 * pointing at the same text. Mentioned ranges are never rewritten.
 */
export function redactPrompt(prompt: PromptDraft, vault: SecretVault): string[] {
  const { text } = prompt;
  const mentions = [...(prompt.files ?? []), ...(prompt.agents ?? []), ...(prompt.skills ?? [])]
    .map((item) => item.mention)
    .filter(
      (m): m is Mention =>
        m !== undefined && m.start >= 0 && m.start <= m.end && m.end <= text.length,
    );

  const boundaries = Array.from(
    new Set([0, text.length, ...mentions.flatMap((m) => [m.start, m.end])]),
  ).sort((a, b) => a - b);
  const isMentioned = (start: number, end: number) =>
    mentions.some((m) => m.start <= start && end <= m.end);

  const labels: string[] = [];
  const offsets = new Map<number, number>([[0, 0]]);
  let result = "";
  for (let i = 0; i < boundaries.length - 1; i++) {
    const start = boundaries[i];
    const end = boundaries[i + 1];
    const segment = text.slice(start, end);
    if (isMentioned(start, end)) {
      result += segment;
    } else {
      const redacted = redactString(segment, vault);
      result += redacted.text;
      labels.push(...redacted.labels);
    }
    offsets.set(end, result.length);
  }

  prompt.text = result;
  for (const mention of new Set(mentions)) {
    mention.start = offsets.get(mention.start) ?? mention.start;
    mention.end = offsets.get(mention.end) ?? mention.end;
  }
  return labels;
}

/** Redacts model-visible text, tool calls, and tool results in place. */
export function redactMessages(messages: ReadonlyArray<MessageLike>, vault: SecretVault): string[] {
  const labels: string[] = [];
  for (const message of messages) {
    for (const part of message.content as ReadonlyArray<MutablePart>) {
      if (part.type === "text" && typeof part.text === "string") {
        const result = redactString(part.text, vault);
        part.text = result.text;
        labels.push(...result.labels);
      } else if (part.type === "tool-call") {
        const result = redactDeep(part.input, vault);
        part.input = result.value;
        labels.push(...result.labels);
      } else if (part.type === "tool-result" && isRecord(part.result)) {
        const value =
          part.result.type === "content"
            ? redactContent(part.result.value, vault, labels)
            : redactValue(part.result.value, vault, labels);
        part.result = { ...part.result, value };
      }
    }
  }
  return labels;
}

/** Redacts `string | Content[]` tool content, leaving file entries untouched. */
export function redactContent(content: unknown, vault: SecretVault, labels: string[]): unknown {
  if (typeof content === "string") return redactValue(content, vault, labels);
  if (!Array.isArray(content)) return content;
  return content.map((item) =>
    isRecord(item) && item.type === "text" && typeof item.text === "string"
      ? { ...item, text: redactValue(item.text, vault, labels) }
      : item,
  );
}

function redactValue(value: unknown, vault: SecretVault, labels: string[]): unknown {
  const result = redactDeep(value, vault);
  labels.push(...result.labels);
  return result.value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// OpenCode 2 implementation, loaded through `setup()` on the default export
export const SecretRedactorV2: Plugin.Plugin = {
  id: "secret-redactor",
  async setup(ctx) {
    const vault = createVault();
    const rpc = await ctx.rpc.register(SecretRedactorRpc, {});

    const notify = (event: RedactedEvent) => {
      rpc.events.emit("redacted", { ...event }).catch(() => {});
    };

    await ctx.session.hook("prompt", (event) => {
      const labels = redactPrompt(event.prompt, vault);
      if (labels.length === 0) return;
      notify({
        message: `Redacted ${labels.length} secret(s) from chat: ${uniqueTypes(labels).join(", ")}`,
        sessionID: event.sessionID,
      });
    });

    // Each model request kind has its own hook; all of them carry transcript history.
    const redactRequest = (event: { sessionID: string; messages: ReadonlyArray<MessageLike> }) => {
      const labels = redactMessages(event.messages, vault);
      if (labels.length === 0) return;
      notify({
        message: `Redacted ${labels.length} secret(s) from LLM context`,
        sessionID: event.sessionID,
      });
    };
    await ctx.session.hook("context", redactRequest);
    await ctx.session.hook("compaction", redactRequest);
    await ctx.session.hook("generate", redactRequest);
    await ctx.session.hook("title", redactRequest);

    await ctx.tool.hook("execute.before", (event) => {
      if (!isToolInScope(event.tool, UNREDACT_ARGS_TOOLS)) return;
      event.input = unredactDeep(event.input, vault);
    });

    await ctx.tool.hook("execute.after", (event) => {
      if (!isToolInScope(event.tool, REDACT_OUTPUT_TOOLS)) return;

      const labels: string[] = [];
      if (event.status === "completed") {
        const { result } = event;
        event.result = {
          ...result,
          ...(result.content !== undefined && {
            content: redactContent(result.content, vault, labels) as typeof result.content,
          }),
          ...(result.output !== undefined && { output: redactValue(result.output, vault, labels) }),
        };
      } else {
        // stderr and failure messages are shown to the model too
        const error = event.error as { message: string };
        error.message = redactValue(error.message, vault, labels) as string;
      }

      if (labels.length === 0) return;
      notify({
        message: `Redacted ${labels.length} secret(s) from ${event.tool}: ${uniqueTypes(labels).join(", ")}`,
        sessionID: event.sessionID,
      });
    });
  },
};
