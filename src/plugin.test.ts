import { describe, expect, it } from "vitest";
import plugin from "./plugin.js";
import { SecretRedactor } from "./v1.js";
import { SecretRedactorV2 } from "./v2.js";

describe("default export", () => {
  it("exposes the OpenCode 2 definition and the OpenCode 1 server entry", () => {
    expect(plugin.id).toBe(SecretRedactorV2.id);
    expect(plugin.setup).toBe(SecretRedactorV2.setup);
    expect(plugin.server).toBe(SecretRedactor);
  });
});
