import { describe, expect, it } from 'vitest';
import { flowSearch } from './search';

describe('flowSearch', () => {
  it('round-trips the new arrays and strings', () => {
    const v = { kind: ['ca', 'client'], status: ['failed', 'idle'], issuer: ['ca:1'], client: ['client:2'], edge: 'a>b', more: ['issuers.cas'] };
    expect(flowSearch.parse(v)).toEqual(v);
  });
  it('keeps the legacy problems alias and drops junk', () => {
    expect(flowSearch.parse({ status: 'problems' }).status).toBe('problems');
    expect(flowSearch.parse({ status: 'bogus' }).status).toBeUndefined();
    expect(flowSearch.parse({ kind: ['nope'] }).kind).toBeUndefined();
  });
  it('omits absent filters', () => {
    expect(flowSearch.parse({})).toEqual({});
  });
});
