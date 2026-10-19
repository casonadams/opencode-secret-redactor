import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { PATTERNS, type SecretPattern } from "./patterns.js";

export const REDACT_OUTPUT_TOOLS = ["shell", "read", "grep", "webfetch"] as const;
export const UNREDACT_ARGS_TOOLS = ["shell", "write", "edit"] as const;
export const MIN_SECRET_LENGTH = 8;
export const REDACTED_PREFIX = "🔒";
export const REDACTED_SUFFIX = "🔓";

export const CONFIG_FILE_NAME = "secret-redactor.json";

export interface ExtraPattern {
  readonly label: string;
  // Regex source, e.g. "acme_[a-f0-9]{32}". Flags default to "g".
  readonly pattern: string;
  readonly flags?: string;
}

export interface RedactorConfig {
  // Pattern labels to turn on (only meaningful for defaultEnabled: false).
  readonly enable: readonly string[];
  // Pattern labels to turn off. Wins over `enable`.
  readonly disable: readonly string[];
  readonly minLength: number;
  readonly extraPatterns: readonly ExtraPattern[];
}

export interface ResolvedConfig {
  readonly patterns: ReadonlyArray<SecretPattern>;
  readonly minLength: number;
}

export const DEFAULT_CONFIG: RedactorConfig = {
  enable: [],
  disable: [],
  minLength: MIN_SECRET_LENGTH,
  extraPatterns: [],
};

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string");
}

function asExtraPatterns(value: unknown): ExtraPattern[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (typeof entry !== "object" || entry === null) return [];
    const { label, pattern, flags } = entry as Record<string, unknown>;
    if (typeof label !== "string" || typeof pattern !== "string") return [];
    return [{ label, pattern, flags: typeof flags === "string" ? flags : undefined }];
  });
}

type MutableConfig = {
  enable?: string[];
  disable?: string[];
  minLength?: number;
  extraPatterns?: ExtraPattern[];
};

function sanitize(config: Record<string, unknown>): MutableConfig {
  const minLength = config.minLength;
  return {
    enable: asStringList(config.enable),
    disable: asStringList(config.disable),
    extraPatterns: asExtraPatterns(config.extraPatterns),
    ...(typeof minLength === "number" && Number.isFinite(minLength) && minLength >= 0
      ? { minLength }
      : {}),
  };
}

function mergeConfig(...layers: Array<Partial<RedactorConfig>>): Partial<RedactorConfig> {
  const enable = new Set<string>();
  const disable = new Set<string>();
  const extraPatterns: ExtraPattern[] = [];
  let minLength: number | undefined;

  for (const layer of layers) {
    for (const label of layer.enable ?? []) enable.add(label);
    for (const label of layer.disable ?? []) disable.add(label);
    extraPatterns.push(...(layer.extraPatterns ?? []));
    if (layer.minLength !== undefined) minLength = layer.minLength;
  }

  return { enable: [...enable], disable: [...disable], extraPatterns, minLength };
}

function readConfigFile(path: string): Partial<RedactorConfig> | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof parsed !== "object" || parsed === null) throw new Error("not a JSON object");
    return sanitize(parsed as Record<string, unknown>);
  } catch (error) {
    console.warn(`[secret-redactor] ignoring invalid config file ${path}: ${error}`);
    return undefined;
  }
}

function parseList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function globalConfigPath(env: NodeJS.ProcessEnv): string {
  const configDir = env.OPENCODE_CONFIG_DIR ?? join(homedir(), ".config", "opencode");
  return join(configDir, CONFIG_FILE_NAME);
}

// Layered config, later layers win: defaults < global file < project file
// < SECRET_REDACTOR_CONFIG file < SECRET_REDACTOR_ENABLE/DISABLE env lists.
// When SECRET_REDACTOR_CONFIG is set it replaces the implicit files, which
// keeps tests and one-off runs hermetic.
export function loadConfig(
  directory?: string,
  env: NodeJS.ProcessEnv = process.env,
): Partial<RedactorConfig> {
  const layers: Array<Partial<RedactorConfig>> = [];

  const explicitPath = env.SECRET_REDACTOR_CONFIG;
  if (explicitPath) {
    layers.push(readConfigFile(explicitPath) ?? {});
  } else {
    layers.push(readConfigFile(globalConfigPath(env)) ?? {});
    if (directory) {
      layers.push(readConfigFile(join(directory, ".opencode", CONFIG_FILE_NAME)) ?? {});
    }
  }

  const envOverrides = sanitize({
    enable: parseList(env.SECRET_REDACTOR_ENABLE),
    disable: parseList(env.SECRET_REDACTOR_DISABLE),
  });
  layers.push(envOverrides);

  return mergeConfig(...layers);
}

function compileExtra(extra: ExtraPattern): SecretPattern | undefined {
  try {
    return { label: extra.label, pattern: new RegExp(extra.pattern, extra.flags ?? "g") };
  } catch (error) {
    console.warn(`[secret-redactor] ignoring invalid extra pattern "${extra.label}": ${error}`);
    return undefined;
  }
}

export function resolveConfig(config: Partial<RedactorConfig> = {}): ResolvedConfig {
  const enable = new Set(config.enable ?? []);
  const disable = new Set(config.disable ?? []);

  const patterns = PATTERNS.filter(
    (entry) =>
      !disable.has(entry.label) && (entry.defaultEnabled !== false || enable.has(entry.label)),
  );
  const extra = (config.extraPatterns ?? [])
    .map(compileExtra)
    .filter((entry): entry is SecretPattern => entry !== undefined);

  return {
    patterns: [...patterns, ...extra],
    minLength: config.minLength ?? MIN_SECRET_LENGTH,
  };
}

let current: ResolvedConfig = resolveConfig();

export function configure(config: Partial<RedactorConfig>): ResolvedConfig {
  current = resolveConfig(config);
  return current;
}

export function getConfig(): ResolvedConfig {
  return current;
}
