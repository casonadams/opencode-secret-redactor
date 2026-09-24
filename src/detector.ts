import { MIN_SECRET_LENGTH } from "./config.js";
import { isLuhnValid } from "./luhn.js";
import { PATTERNS, type SecretPattern } from "./patterns.js";

export interface DetectedSecret {
  readonly label: string;
  readonly value: string;
}

export function detectSecrets(
  text: string,
  patterns: ReadonlyArray<SecretPattern> = PATTERNS,
): ReadonlyArray<DetectedSecret> {
  const found: DetectedSecret[] = [];
  const seen = new Set<string>();

  for (const { label, pattern } of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match = regex.exec(text);
    while (match !== null) {
      const value = match[1] ?? match[0];
      const isCreditCard = label === "credit_card";
      if (
        !seen.has(value) &&
        value.length >= MIN_SECRET_LENGTH &&
        (!isCreditCard || isLuhnValid(value))
      ) {
        seen.add(value);
        found.push({ label: `${label}_${seen.size}`, value });
      }
      match = regex.exec(text);
    }
  }

  return found;
}
