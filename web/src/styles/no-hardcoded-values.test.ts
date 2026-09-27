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
// Excludes a docs anchor like "certificates.md#caa" or "agent.md#abc123": a
// hex-looking word right after ".md#" is a heading slug, not a colour.
const HEX_COLOR = /(?<!\.md)#[0-9A-Fa-f]{6}\b|(?<!\.md)#[0-9A-Fa-f]{3}\b/g;

// Fix round 1 (review): a `learnMore`/href docs anchor such as
// 'certificates.md#caa' used to have to be string-split in source (e.g.
// `'certificates.md' + '#' + 'caa'`) just to dodge this scanner, since "caa"
// happens to be valid 3-digit hex. The lookbehind above lets a real anchor
// stay a plain literal while a genuine hardcoded colour is still caught.
it('does not flag a .md# docs anchor as a hex colour, but still flags a real one', () => {
  expect('see certificates.md#caa for details'.match(HEX_COLOR)).toBeNull();
  expect('learnMore: \'agent.md#abc123\''.match(HEX_COLOR)).toBeNull();
  expect('color: #eab308;'.match(HEX_COLOR)).toEqual(['#eab308']);
  expect('color: #eee;'.match(HEX_COLOR)).toEqual(['#eee']);
});

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
