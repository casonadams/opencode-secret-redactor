export { type DetectedSecret, detectSecrets } from "./detector.js";
export { PATTERNS, type SecretPattern } from "./patterns.js";
// OpenCode resolves npm plugins via the default export
export { default } from "./plugin.js";
export { type RedactResult, redactDeep, unredactDeep } from "./redactor.js";
export { type RedactedEvent, SecretRedactorRpc } from "./rpc.js";
export { SecretRedactorTui } from "./tui.js";
export { SecretRedactor } from "./v1.js";
export { redactContent, redactMessages, redactPrompt, SecretRedactorV2 } from "./v2.js";
export { createVault, type SecretVault } from "./vault.js";
