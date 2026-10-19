import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecretRedactor } from "./plugin.js";

// Fake but well-formed values so the built-in patterns match them.
const GITHUB_PAT = `ghp_${"a".repeat(36)}`;
const JWT = `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.${"b".repeat(24)}`;

const tempDirs: string[] = [];

function makeDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function writeProjectConfig(project: string, config: unknown): void {
  mkdirSync(join(project, ".opencode"), { recursive: true });
  writeFileSync(join(project, ".opencode", "secret-redactor.json"), JSON.stringify(config));
}

type Hook = (event: any) => Promise<void> | void;

// Minimal stand-in for the OpenCode v2 plugin context: records every hook the
// plugin registers so tests can invoke them directly.
function createMockContext(directory?: string) {
  const hooks = new Map<string, Hook>();
  const register =
    (domain: string) =>
    async (name: string, callback: Hook): Promise<{ dispose: () => Promise<void> }> => {
      hooks.set(`${domain}.${name}`, callback);
      return { dispose: async () => void hooks.delete(`${domain}.${name}`) };
    };
  const ctx = {
    location: { directory: directory ?? process.cwd() },
    session: { hook: register("session") },
    tool: { hook: register("tool") },
  };
  return { hooks, ctx };
}

async function loadHooks(directory?: string): Promise<Map<string, Hook>> {
  const { hooks, ctx } = createMockContext(directory);
  await SecretRedactor.setup(ctx as never);
  return hooks;
}

// Keep tests independent from any real global opencode config file.
beforeEach(() => {
  vi.stubEnv("OPENCODE_CONFIG_DIR", makeDir("secret-redactor-global-"));
  vi.stubEnv("SECRET_REDACTOR_CONFIG", "");
  vi.stubEnv("SECRET_REDACTOR_ENABLE", "");
  vi.stubEnv("SECRET_REDACTOR_DISABLE", "");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("SecretRedactor plugin (v2)", () => {
  it("registers hooks on the session and tool domains", async () => {
    const hooks = await loadHooks();

    expect([...hooks.keys()].sort()).toEqual([
      "session.compaction",
      "session.context",
      "session.generate",
      "session.prompt",
      "session.title",
      "tool.execute.after",
      "tool.execute.before",
    ]);
  });

  it("redacts secrets in the prompt hook", async () => {
    const hooks = await loadHooks();
    const event = { prompt: { text: `my token is ${GITHUB_PAT}` } };

    await hooks.get("session.prompt")?.(event);

    expect(event.prompt.text).toMatch(/^my token is 🔒github_pat_\d+🔓$/);
  });

  it("redacts text, tool-call input, tool-result value and system instructions", async () => {
    const hooks = await loadHooks();
    const event = {
      messages: [
        { content: [{ type: "text", text: `key ${GITHUB_PAT}` }] },
        { content: [{ type: "tool-call", input: { command: `curl ${JWT}` } }] },
        { content: [{ type: "tool-result", result: { value: `out ${JWT}` } }] },
      ],
      system: [{ text: `sys ${GITHUB_PAT}` }],
    };

    await hooks.get("session.context")?.(event);

    expect(event.messages[0].content[0].text).toMatch(/^key 🔒github_pat_\d+🔓$/);
    expect(event.messages[1].content[0].input.command).toMatch(/^curl 🔒jwt_\d+🔓$/);
    expect(event.messages[2].content[0].result.value).toMatch(/^out 🔒jwt_\d+🔓$/);
    expect(event.system[0].text).toMatch(/^sys 🔒github_pat_\d+🔓$/);
  });

  it("redacts secrets in shell tool output", async () => {
    const hooks = await loadHooks();
    const event = { tool: "shell", status: "completed", result: { output: `token: ${JWT}` } };

    await hooks.get("tool.execute.after")?.(event);

    expect(event.result.output).toMatch(/^token: 🔒jwt_\d+🔓$/);
  });

  it("skips tools not in scope", async () => {
    const hooks = await loadHooks();
    const event = { tool: "glob", status: "completed", result: { output: JWT } };

    await hooks.get("tool.execute.after")?.(event);

    expect(event.result.output).toBe(JWT);
  });

  it("ignores failed tool executions", async () => {
    const hooks = await loadHooks();
    const event = { tool: "shell", status: "error", error: { message: JWT } };

    await hooks.get("tool.execute.after")?.(event);

    expect(event.error.message).toBe(JWT);
  });

  it("restores secrets in tool arguments before execution", async () => {
    const hooks = await loadHooks();

    const redacted = { tool: "shell", status: "completed", result: { output: JWT } };
    await hooks.get("tool.execute.after")?.(redacted);
    const token = redacted.result.output;

    const args = { tool: "shell", input: { command: `curl -H 'Bearer ${token}'` } };
    await hooks.get("tool.execute.before")?.(args);

    expect(args.input.command).toBe(`curl -H 'Bearer ${JWT}'`);
  });

  it("does not redact email addresses by default", async () => {
    const hooks = await loadHooks();
    const event = {
      tool: "read",
      status: "completed",
      result: { output: "contact john.doe@example.com for info" },
    };

    await hooks.get("tool.execute.after")?.(event);

    expect(event.result.output).toBe("contact john.doe@example.com for info");
  });

  it("redacts email addresses when the project config enables the pattern", async () => {
    const project = makeDir("secret-redactor-project-");
    writeProjectConfig(project, { enable: ["email"] });
    const hooks = await loadHooks(project);
    const event = {
      tool: "read",
      status: "completed",
      result: { output: "contact john.doe@example.com for info" },
    };

    await hooks.get("tool.execute.after")?.(event);

    expect(event.result.output).toMatch(/^contact 🔒email_\d+🔓 for info$/);
  });

  it("does not redact placeholder values such as ${DB_PASSWORD}", async () => {
    const hooks = await loadHooks();
    const event = {
      tool: "read",
      status: "completed",
      result: { output: "password: ${DB_PASSWORD}" },
    };

    await hooks.get("tool.execute.after")?.(event);

    expect(event.result.output).toBe("password: ${DB_PASSWORD}");
  });

  it("honours SECRET_REDACTOR_DISABLE from the environment", async () => {
    vi.stubEnv("SECRET_REDACTOR_DISABLE", "github_pat");

    const hooks = await loadHooks();
    const event = {
      tool: "shell",
      status: "completed",
      result: { output: `token: ${GITHUB_PAT}` },
    };

    await hooks.get("tool.execute.after")?.(event);

    expect(event.result.output).toBe(`token: ${GITHUB_PAT}`);
  });
});
