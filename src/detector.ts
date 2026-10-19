import { getConfig } from "./config.js";
import type { SecretPattern } from "./patterns.js";

export interface DetectedSecret {
  readonly label: string;
  readonly value: string;
}

// A whole value that is a variable reference or template, not a literal
// secret: $PASS, ${DB_PASSWORD}, {some_pass}, {{ password }}, %DB_PASS%,
// <<PASS>>, $(PASS), __SECRET__, ${{ secrets.FOO }}.
// Anchored: a literal containing a "$" or "{" (bcrypt hashes, passwords)
// is never skipped, so this fails closed.
const PLACEHOLDER_PATTERN =
  /^(?:\$\{\{[^}]*\}\}|\$\([^)]*\)|\$\{[^}]*\}|\$[A-Za-z_]\w*|\{\{[^}]*\}\}|<<[^>]*>>|<[^>]*>|\{[^}]*\}|%\{[^}]*\}|%[^%{}]+%|__[A-Za-z_]\w*__)$/;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERN.test(value);
}

export function detectSecrets(
  text: string,
  patterns: ReadonlyArray<SecretPattern> = getConfig().patterns,
  minLength: number = getConfig().minLength,
): ReadonlyArray<DetectedSecret> {
  const found: DetectedSecret[] = [];
  const seen = new Set<string>();

  for (const { label, pattern } of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match = regex.exec(text);
    while (match !== null) {
      const value = match[1] ?? match[0];
      if (!seen.has(value) && value.length >= minLength && !isPlaceholder(value)) {
        seen.add(value);
        found.push({ label: `${label}_${seen.size}`, value });
      }
      match = regex.exec(text);
    }
  }

  return found;
}
