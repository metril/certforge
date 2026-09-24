// @vitest-environment node
// Guards the "every colour/radius/shadow comes from tokens.css" rule (spec:
// Visual direction) against regressions: Tailwind arbitrary-value escape
// hatches and raw hex colours outside the token file.
import { readdirSync, readFileSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC = resolve(import.meta.dirname, '../..', 'src');
const SELF = resolve(import.meta.dirname, 'no-hardcoded-values.test.ts');
const TOKENS_CSS = resolve(import.meta.dirname, 'tokens.css');

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) return walk(full);
    if (!/\.(ts|tsx|css)$/.test(entry.name)) return [];
    return [full];
  });
}

const files = walk(SRC).filter((f) => f !== SELF);

// Built as concatenations so this file's own forbidden-pattern strings don't
// trip the check on itself.
const ROUNDED_ARBITRARY = 'rounded-' + '[';
const SHADOW_ARBITRARY = 'shadow-' + '[';
const HEX_COLOR = /#[0-9A-Fa-f]{6}\b|#[0-9A-Fa-f]{3}\b/g;

describe('no hardcoded arbitrary radii, shadows, or hex colours outside tokens.css', () => {
  it.each(files.map((f) => [relative(SRC, f).split(sep).join('/'), f] as const))('%s', (_, file) => {
    const content = readFileSync(file, 'utf8');
    expect(content.includes(ROUNDED_ARBITRARY), `${ROUNDED_ARBITRARY} arbitrary radius`).toBe(false);
    expect(content.includes(SHADOW_ARBITRARY), `${SHADOW_ARBITRARY} arbitrary shadow`).toBe(false);
    if (file !== TOKENS_CSS) {
      expect(content.match(HEX_COLOR), 'hex colour outside tokens.css').toBeNull();
    }
  });
});
