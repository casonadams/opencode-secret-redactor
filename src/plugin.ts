import { SecretRedactor } from "./v1.js";
import { SecretRedactorV2 } from "./v2.js";

// One default export for both generations: OpenCode 2 calls `setup()`,
// OpenCode 1 (1.18.29 and newer) calls `server()`.
export default {
  ...SecretRedactorV2,
  server: SecretRedactor,
};
