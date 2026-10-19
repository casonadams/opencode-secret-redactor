import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { configure, DEFAULT_CONFIG, getConfig, loadConfig, resolveConfig } from "./config.js";
import { detectSecrets } from "./detector.js";
import { PATTERNS } from "./patterns.js";

const tempDirs: string[] = [];

function makeDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function writeConfig(dir: string, config: unknown): void {
  writeFileSync(join(dir, "secret-redactor.json"), JSON.stringify(config));
}

function emptyEnv(configDir: string): NodeJS.ProcessEnv {
  return { OPENCODE_CONFIG_DIR: configDir };
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  configure({});
  vi.restoreAllMocks();
});

describe("resolveConfig", () => {
  it("enables every pattern except the ones marked defaultEnabled: false", () => {
    const { patterns } = resolveConfig();

    expect(patterns.map((entry) => entry.label)).toEqual(
      PATTERNS.filter((entry) => entry.defaultEnabled !== false).map((entry) => entry.label),
    );
    expect(patterns.map((entry) => entry.label)).not.toContain("email");
  });

  it("turns a pattern off through disable", () => {
    const { patterns } = resolveConfig({ disable: ["github_pat"] });

    expect(patterns.map((entry) => entry.label)).not.toContain("github_pat");
    expect(patterns.map((entry) => entry.label)).toContain("gitlab_pat");
  });

  it("turns an off-by-default pattern on through enable", () => {
    const { patterns } = resolveConfig({ enable: ["email"] });

    expect(patterns.map((entry) => entry.label)).toContain("email");
  });

  it("lets disable win over enable", () => {
    const { patterns } = resolveConfig({ enable: ["email"], disable: ["email"] });

    expect(patterns.map((entry) => entry.label)).not.toContain("email");
  });

  it("overrides the minimum secret length", () => {
    const { minLength } = resolveConfig({ minLength: 4 });

    expect(minLength).toBe(4);
    expect(resolveConfig().minLength).toBe(DEFAULT_CONFIG.minLength);
  });

  it("appends extra patterns", () => {
    const { patterns } = resolveConfig({
      extraPatterns: [{ label: "acme_token", pattern: "acme_[a-f0-9]{32}" }],
    });

    expect(patterns.at(-1)?.label).toBe("acme_token");
    expect(detectSecrets("key: acme_0123456789abcdef0123456789abcdef", patterns, 8)).toHaveLength(
      1,
    );
  });

  it("ignores extra patterns that are not valid regular expressions", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { patterns } = resolveConfig({
      extraPatterns: [{ label: "broken", pattern: "([" }],
    });

    expect(patterns.map((entry) => entry.label)).not.toContain("broken");
    expect(console.warn).toHaveBeenCalled();
  });
});

describe("loadConfig", () => {
  it("reads the global config file from the opencode config dir", () => {
    const configDir = makeDir("secret-redactor-global-");
    writeConfig(configDir, { disable: ["email"], minLength: 12 });

    expect(loadConfig(undefined, emptyEnv(configDir))).toEqual({
      enable: [],
      disable: ["email"],
      minLength: 12,
      extraPatterns: [],
    });
  });

  it("layers the project config file on top of the global one", () => {
    const configDir = makeDir("secret-redactor-global-");
    writeConfig(configDir, { disable: ["email", "credit_card"] });
    const project = makeDir("secret-redactor-project-");
    mkdirSync(join(project, ".opencode"));
    writeConfig(join(project, ".opencode"), { disable: ["us_ssn"] });

    const config = loadConfig(project, emptyEnv(configDir));

    expect(config.disable).toEqual(["email", "credit_card", "us_ssn"]);
  });

  it("replaces the implicit files when SECRET_REDACTOR_CONFIG is set", () => {
    const configDir = makeDir("secret-redactor-global-");
    writeConfig(configDir, { disable: ["email"] });
    const project = makeDir("secret-redactor-project-");
    mkdirSync(join(project, ".opencode"));
    writeConfig(join(project, ".opencode"), { disable: ["credit_card"] });
    const explicitDir = makeDir("secret-redactor-explicit-");
    writeConfig(explicitDir, { disable: ["us_ssn"] });

    const config = loadConfig(project, {
      ...emptyEnv(configDir),
      SECRET_REDACTOR_CONFIG: join(explicitDir, "secret-redactor.json"),
    });

    expect(config.disable).toEqual(["us_ssn"]);
  });

  it("merges the env list overrides last", () => {
    const configDir = makeDir("secret-redactor-global-");
    writeConfig(configDir, { disable: ["email"] });

    const config = loadConfig(undefined, {
      ...emptyEnv(configDir),
      SECRET_REDACTOR_ENABLE: "email, phone_us",
      SECRET_REDACTOR_DISABLE: "credit_card",
    });

    expect(config.enable).toEqual(["email", "phone_us"]);
    expect(config.disable).toEqual(["email", "credit_card"]);
  });

  it("returns defaults when no config file exists", () => {
    const configDir = makeDir("secret-redactor-global-");

    expect(loadConfig(undefined, emptyEnv(configDir))).toEqual({
      enable: [],
      disable: [],
      extraPatterns: [],
    });
  });

  it("ignores a config file that is not valid JSON", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const configDir = makeDir("secret-redactor-global-");
    writeFileSync(join(configDir, "secret-redactor.json"), "{ not json");

    expect(loadConfig(undefined, emptyEnv(configDir))).toEqual({
      enable: [],
      disable: [],
      extraPatterns: [],
    });
    expect(console.warn).toHaveBeenCalled();
  });

  it("ignores fields of the wrong type", () => {
    const configDir = makeDir("secret-redactor-global-");
    writeConfig(configDir, { disable: "email", minLength: "8", enable: [42] });

    const config = loadConfig(undefined, emptyEnv(configDir));

    expect(config.disable).toEqual([]);
    expect(config.minLength).toBeUndefined();
    expect(config.enable).toEqual([]);
  });
});

describe("configure", () => {
  it("feeds detectSecrets with the resolved patterns", () => {
    const configDir = makeDir("secret-redactor-global-");
    writeConfig(configDir, { disable: ["jwt"] });

    configure(loadConfig(undefined, emptyEnv(configDir)));

    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(detectSecrets(`token: ${jwt}`)).toHaveLength(0);
    expect(getConfig().patterns.map((entry) => entry.label)).not.toContain("jwt");
  });
});
