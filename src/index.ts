export { type DetectedSecret, detectSecrets } from "./detector.js";
export { PATTERNS, type SecretPattern } from "./patterns.js";
// OpenCode resolves npm plugins via the default export
export { default, SecretRedactor } from "./plugin.js";
export { type RedactResult, redactDeep, unredactDeep } from "./redactor.js";
export { createVault, type SecretVault } from "./vault.js";
