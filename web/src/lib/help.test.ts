import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { explainAcmeError } from './acmeErrors';
import { firstSentences, help, type Help } from './help';

const docs = resolve(import.meta.dirname, '../../../docs');
const githubSlug = (h: string) => h.trim().toLowerCase().replace(/[^\w\- ]+/g, '').replace(/ /g, '-');
const entries = Object.entries(help) as [string, Help][];

describe('help copy', () => {
  it.each(entries)('%s is at most two short sentences', (_, h) => {
    expect(h.text.split(/(?<=[.!?])\s+/).filter(Boolean).length).toBeLessThanOrEqual(2);
    expect(h.text.length).toBeLessThanOrEqual(160);
  });
  const hasAnchor = (ref: string) => {
    const [file, anchor] = ref.split('#');
    const md = readFileSync(resolve(docs, file!), 'utf8');
    const anchors = [...md.matchAll(/^#{1,6}\s+(.+)$/gm)].map((m) => githubSlug(m[1]!));
    return anchors.includes(anchor!);
  };
  it('docs use no {#id} anchors, which GitHub does not support', () => {
    for (const f of ['operations/security-model.md', 'internals/architecture.md']) {
      expect(readFileSync(resolve(docs, f), 'utf8')).not.toContain('{#');
    }
  });
  it.each(entries.filter(([, h]) => h.learnMore))('%s links to an existing doc heading', (_, h) => {
    expect(hasAnchor(h.learnMore!)).toBe(true);
  });
  const acmeTypes = ['rateLimited', 'dns', 'unauthorized', 'incorrectResponse', 'caa', 'connection', 'rejectedIdentifier', 'externalAccountRequired', 'accountDoesNotExist', 'badNonce', 'serverInternal', 'malformed', 'orderNotReady', 'unknownType'];
  it.each(acmeTypes)('acme error %s links to an existing doc heading', (t) => {
    expect(hasAnchor(explainAcmeError(`urn:ietf:params:acme:error:${t}`)!.href)).toBe(true);
  });
  it('trims schema descriptions to two sentences', () => {
    expect(firstSentences('One. Two! Three? Four.', 2)).toBe('One. Two!');
  });
});
