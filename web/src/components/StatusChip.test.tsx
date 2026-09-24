// Fix round 1: this file grew a render test (#5), which needs a DOM, so the
// node-only test environment this file used to force is gone; the project's
// default jsdom environment still runs under real Node, so the `node:fs`/
// `node:path` reads below work unchanged.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { CertStatus } from '@/api/types';
import { STATUS_META } from '@/lib/status';
import { CHIP, CHIP_TINT, StatusChip } from './StatusChip';

// Controller ruling (Task 6): chip words use the `ink` token in both themes;
// this proves each tone's real background — panel blended with the tone
// colour at CHIP_TINT's own alpha, exactly what the rendered `bg-<tone>/NN`
// utility produces — still clears 4.5:1 against ink. `expired` and `failed`
// are covered by styles/tokens.test.ts (on-status vs expired/failed, and ink
// vs panel/subtle for the outlined/neutral chips) so they are not repeated
// here.
const css = readFileSync(resolve(import.meta.dirname, '../styles/tokens.css'), 'utf8');

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
function toRgb(hex: string): [number, number, number] {
  return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as [number, number, number];
}
function toHex(rgb: [number, number, number]): string {
  return '#' + rgb.map((c) => Math.round(c).toString(16).padStart(2, '0')).join('');
}
/** panel blended with `fg` at `alpha`, matching how `bg-<tone>/NN` renders over the panel behind it. */
function tint(fg: string, bg: string, alpha: number): string {
  const [fr, fg2, fb] = toRgb(fg);
  const [br, bgg, bb] = toRgb(bg);
  return toHex([fr * alpha + br * (1 - alpha), fg2 * alpha + bgg * (1 - alpha), fb * alpha + bb * (1 - alpha)]);
}

const TINTED_TONES = ['valid', 'expiring', 'drift'] as const;

describe.each([
  ['light', light],
  ['dark', dark],
] as const)('%s chip tints', (_, t) => {
  it.each(TINTED_TONES)('ink on the %s chip background meets 4.5:1', (tone) => {
    const bg = tint(t[tone]!, t.panel!, CHIP_TINT[tone]);
    expect(contrast(t.ink!, bg)).toBeGreaterThanOrEqual(4.5);
  });
});

// Fix round 1 (#5): the contrast test above recomputes each tinted chip's
// background from CHIP_TINT's alpha, not from the CHIP class string itself —
// so if StatusChip.tsx's `bg-<tone>/NN` class ever drifts from CHIP_TINT, the
// contrast test would keep passing against a background the component no
// longer renders. Pin the two together directly.
it.each(TINTED_TONES)('the %s chip class actually uses CHIP_TINT’s alpha', (tone) => {
  const pct = CHIP_TINT[tone] * 100;
  expect(CHIP[tone]).toContain(`bg-${tone}/${pct}`);
});

// Fix round 1 (#5): every status chip pairs an icon with a word (controller
// ruling), rendered rather than asserted from the class strings.
describe('StatusChip', () => {
  it.each(Object.keys(STATUS_META) as CertStatus[])('%s shows an icon and a word', (status) => {
    const { container } = render(<StatusChip status={status} />);
    expect(container).toHaveTextContent(STATUS_META[status].label);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });
});
