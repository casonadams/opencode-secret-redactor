import { describe, expect, it, vi } from "vitest";
import { SecretRedactorRpc } from "./rpc.js";
import { redactPrompt, SecretRedactorV2 } from "./v2.js";
import { createVault } from "./vault.js";

const GITHUB_TOKEN = "ghp_R8z3kL9mN2pQ5tV7wX0yB4dF6hJ1oS3uA8cE";
const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZmFrZSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

type Hook = (event: Record<string, unknown>) => Promise<void> | void;

async function setup() {
  const hooks = new Map<string, Hook>();
  const emit = vi.fn().mockResolvedValue(undefined);
  const register = vi.fn().mockResolvedValue({ dispose: vi.fn(), events: { emit } });
  const hook = vi.fn(async (name: string, callback: Hook) => {
    hooks.set(name, callback);
    return { dispose: vi.fn() };
  });
  const ctx = { rpc: { register }, session: { hook }, tool: { hook } };

  await SecretRedactorV2.setup(ctx as never);

  const run = async (name: string, event: Record<string, unknown>) => {
    const callback = hooks.get(name);
    if (!callback) throw new Error(`hook ${name} not registered`);
    await callback(event);
    return event;
  };
  return { hooks, emit, register, run };
}

describe("SecretRedactorV2 plugin", () => {
  it("registers the RPC and every hook", async () => {
    const { hooks, register } = await setup();

    expect(SecretRedactorV2.id).toBe("secret-redactor");
    expect(register).toHaveBeenCalledWith(SecretRedactorRpc, {});
    expect([...hooks.keys()].sort()).toEqual([
      "compaction",
      "context",
      "execute.after",
      "execute.before",
      "generate",
      "prompt",
      "title",
    ]);
  });

  it("redacts secrets in the prompt and emits a redacted event", async () => {
    const { emit, run } = await setup();
    const event = await run("prompt", {
      sessionID: "ses_1",
      prompt: { text: `my token is ${GITHUB_TOKEN}` },
    });

    expect((event.prompt as { text: string }).text).toMatch(/^my token is 🔒github_pat_\d+🔓$/);
    expect(emit).toHaveBeenCalledWith("redacted", {
      message: expect.stringContaining("Redacted 1 secret(s) from chat: github_pat"),
      sessionID: "ses_1",
    });
  });

  it("does not emit when nothing is redacted", async () => {
    const { emit, run } = await setup();
    await run("prompt", { sessionID: "ses_1", prompt: { text: "hello" } });
    await run("context", { sessionID: "ses_1", messages: [] });

    expect(emit).not.toHaveBeenCalled();
  });

  it.each([
    "context",
    "compaction",
    "generate",
    "title",
  ])("redacts message history in the %s hook", async (name) => {
    const { emit, run } = await setup();
    const messages = [
      { role: "user", content: [{ type: "text", text: `my key is ${GITHUB_TOKEN}` }] },
      { role: "assistant", content: [{ type: "text", text: "no secrets here" }] },
    ];
    await run(name, { sessionID: "ses_1", messages });

    expect(messages[0].content[0].text).toMatch(/^my key is 🔒github_pat_\d+🔓$/);
    expect(messages[1].content[0].text).toBe("no secrets here");
    expect(emit).toHaveBeenCalledWith("redacted", {
      message: expect.stringContaining("Redacted 1 secret(s) from LLM context"),
      sessionID: "ses_1",
    });
  });

  it("redacts tool calls and every tool result shape in context", async () => {
    const { run } = await setup();
    const file = { type: "file", uri: `file:///${GITHUB_TOKEN}`, mime: "text/plain" };
    const messages = [
      {
        role: "assistant",
        content: [{ type: "tool-call", id: "1", name: "shell", input: { command: `echo ${JWT}` } }],
      },
      {
        role: "tool",
        content: [
          { type: "tool-result", id: "1", name: "shell", result: { type: "text", value: JWT } },
          {
            type: "tool-result",
            id: "2",
            name: "read",
            result: { type: "json", value: { token: GITHUB_TOKEN } },
          },
          {
            type: "tool-result",
            id: "3",
            name: "read",
            result: { type: "content", value: [{ type: "text", text: GITHUB_TOKEN }, file] },
          },
        ],
      },
    ];
    await run("context", { sessionID: "ses_1", messages });

    const [call] = messages[0].content as Array<{ input: { command: string } }>;
    const [text, json, content] = messages[1].content as Array<{
      result: { value: unknown };
    }>;
    expect(call.input.command).toMatch(/^echo 🔒jwt_\d+🔓$/);
    expect(text.result.value).toMatch(/^🔒jwt_\d+🔓$/);
    expect(json.result.value).toEqual({ token: expect.stringMatching(/^🔒github_pat_\d+🔓$/) });
    const [textItem, fileItem] = content.result.value as Array<{ text?: string }>;
    expect(textItem.text).toMatch(/^🔒github_pat_\d+🔓$/);
    expect(fileItem).toBe(file);
  });

  it("leaves reasoning and media parts untouched", async () => {
    const { run } = await setup();
    const reasoning = { type: "reasoning", text: GITHUB_TOKEN, encrypted: "sig" };
    const media = { type: "media", media: { type: "bytes", data: new Uint8Array([1, 2]) } };
    const messages = [{ role: "assistant", content: [reasoning, media] }];
    await run("context", { sessionID: "ses_1", messages });

    expect(messages[0].content[0]).toEqual({
      type: "reasoning",
      text: GITHUB_TOKEN,
      encrypted: "sig",
    });
    expect(messages[0].content[1]).toBe(media);
  });

  it("redacts completed tool content and structured output", async () => {
    const { emit, run } = await setup();
    const event = await run("execute.after", {
      tool: "shell",
      sessionID: "ses_1",
      status: "completed",
      result: {
        content: `token: ${JWT}`,
        output: { stdout: JWT },
        metadata: { exit: 0 },
      },
    });

    const result = event.result as {
      content: string;
      output: { stdout: string };
      metadata: object;
    };
    expect(result.content).toMatch(/^token: 🔒jwt_\d+🔓$/);
    expect(result.output.stdout).toMatch(/^🔒jwt_\d+🔓$/);
    expect(result.metadata).toEqual({ exit: 0 });
    expect(emit).toHaveBeenCalledWith("redacted", {
      message: expect.stringContaining("Redacted 1 secret(s) from shell: jwt"),
      sessionID: "ses_1",
    });
  });

  it("redacts text entries in array tool content", async () => {
    const { run } = await setup();
    const file = { type: "file", uri: "file:///a.png", mime: "image/png" };
    const event = await run("execute.after", {
      tool: "read",
      status: "completed",
      result: { content: [{ type: "text", text: GITHUB_TOKEN }, file] },
    });

    const { content } = event.result as { content: Array<{ text?: string }> };
    expect(content[0].text).toMatch(/^🔒github_pat_\d+🔓$/);
    expect(content[1]).toBe(file);
    expect(event.result).not.toHaveProperty("output");
  });

  it("redacts failed tool error messages", async () => {
    const { run } = await setup();
    const error = { _tag: "Tool.Error", message: `auth failed for ${JWT}` };
    await run("execute.after", { tool: "shell", status: "error", error });

    expect(error.message).toMatch(/^auth failed for 🔒jwt_\d+🔓$/);
  });

  it("skips tool output outside the redaction scope", async () => {
    const { emit, run } = await setup();
    const event = await run("execute.after", {
      tool: "glob",
      status: "completed",
      result: { content: JWT },
    });

    expect((event.result as { content: string }).content).toBe(JWT);
    expect(emit).not.toHaveBeenCalled();
  });

  it("restores redacted values in tool input before execution", async () => {
    const { run } = await setup();
    const after = await run("execute.after", {
      tool: "shell",
      status: "completed",
      result: { content: JWT },
    });
    const placeholder = (after.result as { content: string }).content;

    const before = await run("execute.before", {
      tool: "shell",
      input: { command: `curl -H 'Bearer ${placeholder}'` },
    });
    expect(before.input).toEqual({ command: `curl -H 'Bearer ${JWT}'` });

    const untouched = await run("execute.before", {
      tool: "read",
      input: { path: placeholder },
    });
    expect(untouched.input).toEqual({ path: placeholder });
  });

  it("keeps the vault isolated per plugin instance", async () => {
    const first = await setup();
    const second = await setup();
    const after = await first.run("execute.after", {
      tool: "shell",
      status: "completed",
      result: { content: JWT },
    });
    const placeholder = (after.result as { content: string }).content;

    const before = await second.run("execute.before", {
      tool: "shell",
      input: { command: placeholder },
    });
    expect(before.input).toEqual({ command: placeholder });
  });

  it("swallows RPC emit failures", async () => {
    const { emit, run } = await setup();
    emit.mockRejectedValueOnce(new Error("disconnected"));

    await expect(
      run("prompt", { sessionID: "ses_1", prompt: { text: GITHUB_TOKEN } }),
    ).resolves.toBeDefined();
  });
});

describe("redactPrompt", () => {
  it("shifts mentions that follow a redacted secret", () => {
    const vault = createVault();
    const text = `use ${GITHUB_TOKEN} with @src/a.ts and @build`;
    const fileStart = text.indexOf("@src/a.ts");
    const agentStart = text.indexOf("@build");
    const prompt = {
      text,
      files: [
        {
          uri: "file:///src/a.ts",
          mention: { start: fileStart, end: fileStart + 9, text: "@src/a.ts" },
        },
      ],
      agents: [
        { name: "build", mention: { start: agentStart, end: agentStart + 6, text: "@build" } },
      ],
    };

    const labels = redactPrompt(prompt, vault);

    expect(labels).toHaveLength(1);
    expect(prompt.text).toMatch(/^use 🔒github_pat_\d+🔓 with @src\/a\.ts and @build$/);
    const file = prompt.files[0].mention;
    const agent = prompt.agents[0].mention;
    expect(prompt.text.slice(file.start, file.end)).toBe("@src/a.ts");
    expect(prompt.text.slice(agent.start, agent.end)).toBe("@build");
  });

  it("keeps mentions before the secret in place and never rewrites mentioned text", () => {
    const vault = createVault();
    const text = `@notes.md ${GITHUB_TOKEN}`;
    const mention = { start: 0, end: 9, text: "@notes.md" };
    const prompt = { text, files: [{ mention }] };

    redactPrompt(prompt, vault);

    expect(mention).toEqual({ start: 0, end: 9, text: "@notes.md" });
    expect(prompt.text).toMatch(/^@notes\.md 🔒github_pat_\d+🔓$/);
  });

  it("ignores out-of-range mentions", () => {
    const vault = createVault();
    const mention = { start: 5, end: 500 };
    const prompt = { text: GITHUB_TOKEN, skills: [{ mention }] };

    redactPrompt(prompt, vault);

    expect(prompt.text).toMatch(/^🔒github_pat_\d+🔓$/);
    expect(mention).toEqual({ start: 5, end: 500 });
  });
});
