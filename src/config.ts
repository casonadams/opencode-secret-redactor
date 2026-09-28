// OpenCode 2 renames `bash` to `shell` and folds `write`/`patch` into `edit`;
// both generations are listed so one config serves V1 and V2.
export const REDACT_OUTPUT_TOOLS = ["bash", "shell", "read", "grep", "webfetch"] as const;
export const UNREDACT_ARGS_TOOLS = [
  "bash",
  "shell",
  "write",
  "edit",
  "patch",
  "apply_patch",
] as const;
export const MIN_SECRET_LENGTH = 8;
export const REDACTED_PREFIX = "🔒";
export const REDACTED_SUFFIX = "🔓";
