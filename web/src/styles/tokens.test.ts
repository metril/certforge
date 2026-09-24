// @vitest-environment node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const css = readFileSync(resolve(import.meta.dirname, 'tokens.css'), 'utf8');

function block(selector: RegExp): Record<string, string> {
  const body = css.match(selector)?.[1] ?? '';
  return Object.fromEntries([...body.matchAll(/--cf-([a-z-]+):\s*(#[0-9A-Fa-f]{6})/g)].map((m) => [m[1]!, m[2]!]));
}
const light = block(/:root,\s*\[data-theme="light"\]\s*\{([^}]*)\}/);
const dark = block(/\n\[data-theme="dark"\]\s*\{([^}]*)\}/);

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

const TEXT: [string, string][] = [
  ['ink', 'surface'], ['ink', 'panel'], ['ink', 'subtle'], ['ink-muted', 'panel'], ['ink-muted', 'surface'],
  ['ink-muted', 'subtle'], ['primary', 'panel'], ['on-primary', 'primary'], ['on-status', 'expired'], ['on-status', 'failed'],
];
const TONES = ['valid', 'expiring', 'expired', 'failed', 'drift', 'pending'];

describe.each([['light', light], ['dark', dark]] as const)('%s tokens', (_, t) => {
  it('defines the same token set as the other theme', () => {
    expect(Object.keys(t).sort()).toEqual(Object.keys(light).sort());
  });
  it.each(TEXT)('%s on %s meets 4.5:1', (fg, bg) => {
    expect(contrast(t[fg]!, t[bg]!)).toBeGreaterThanOrEqual(4.5);
  });
  it.each(TONES)('%s reaches 3:1 against panel and surface', (tone) => {
    expect(contrast(t[tone]!, t.panel!)).toBeGreaterThanOrEqual(3);
    expect(contrast(t[tone]!, t.surface!)).toBeGreaterThanOrEqual(3);
  });
});
