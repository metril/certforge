import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { firstSentences, help, type Help } from './help';

const docs = resolve(import.meta.dirname, '../../../docs');
const githubSlug = (h: string) => h.trim().toLowerCase().replace(/[^\w\- ]+/g, '').replace(/ /g, '-');
const entries = Object.entries(help) as [string, Help][];

describe('help copy', () => {
  it.each(entries)('%s is at most two short sentences', (_, h) => {
    expect(h.text.split(/(?<=[.!?])\s+/).filter(Boolean).length).toBeLessThanOrEqual(2);
    expect(h.text.length).toBeLessThanOrEqual(160);
  });
  it.each(entries.filter(([, h]) => h.learnMore))('%s links to an existing doc heading', (_, h) => {
    const [file, anchor] = h.learnMore!.split('#');
    const md = readFileSync(resolve(docs, file!), 'utf8');
    const anchors = [...md.matchAll(/^#{1,6}\s+(.+)$/gm)].map((m) => githubSlug(m[1]!));
    expect(anchors).toContain(anchor);
  });
  it('trims schema descriptions to two sentences', () => {
    expect(firstSentences('One. Two! Three? Four.', 2)).toBe('One. Two!');
  });
});
