import { describe, expect, it } from 'vitest';
import { collapseEdges, edgeKey, filterFlow, pairStatus, tracePath, visibleNodeIds, type Flow, type FlowNodeData } from './flowGraph';

const node = (kind: FlowNodeData['kind'], id: string, extra: Partial<FlowNodeData> = {}): FlowNodeData => ({
  id: `${kind}:${id}`,
  kind,
  name: id,
  status: 'valid',
  href: `/o/acme/x/${id}`,
  ...extra,
});
const lane = (nodes: FlowNodeData[], hidden = false) => ({ hidden, nodes });
const e = (from: string, to: string, certificateId?: string) => ({ from, to, status: 'valid' as const, certificateId });

// Two certificates share CA1 and layout L1; A reaches client K1, B reaches K2.
const flow: Flow = {
  truncated: false,
  generatedAt: '2026-01-01T00:00:00Z',
  lanes: {
    issuers: lane([node('ca', 'ca1'), node('ca', 'ca2'), node('dnsCredential', 'dns1')]),
    certificates: lane([node('certificate', 'A'), node('certificate', 'B'), node('certificate', 'C')]),
    delivery: lane([node('layout', 'L1'), node('hook', 'H1')]),
    clients: lane([node('client', 'K1'), node('client', 'K2'), node('client', 'K3')]),
    alerts: lane([node('channel', 'ch1', { coversCertificates: true }), node('channel', 'ch2')]),
  },
  edges: [
    e('certificate:A', 'ca:ca1'),
    e('certificate:B', 'ca:ca1'),
    e('certificate:B', 'ca:ca2'),
    e('certificate:A', 'dnsCredential:dns1'),
    e('certificate:A', 'layout:L1'),
    e('certificate:B', 'layout:L1'),
    e('layout:L1', 'client:K1', 'A'),
    e('layout:L1', 'client:K2', 'B'),
    e('certificate:B', 'hook:H1'),
    e('hook:H1', 'client:K3', 'B'),
  ],
};

const ids = (s: Set<string>) => [...s].sort();

describe('tracePath', () => {
  it('returns an empty path for no or unknown selection', () => {
    expect(tracePath(flow, null).nodes.size).toBe(0);
    expect(tracePath(flow, 'certificate:nope').nodes.size).toBe(0);
  });

  it('traces a certificate through its issuers, delivery, its own clients and covering channels', () => {
    const p = tracePath(flow, 'certificate:A');
    expect(ids(p.nodes)).toEqual(['ca:ca1', 'certificate:A', 'channel:ch1', 'client:K1', 'dnsCredential:dns1', 'layout:L1']);
    expect(p.edges.has(edgeKey('layout:L1', 'client:K1'))).toBe(true);
    expect(p.edges.has(edgeKey('layout:L1', 'client:K2'))).toBe(false);
    expect(ids(p.synthetic)).toEqual([edgeKey('certificate:A', 'channel:ch1')]);
  });

  it('does not cross-highlight between certificates that share a layout and an issuer', () => {
    const b = tracePath(flow, 'certificate:B');
    expect(b.nodes.has('client:K1')).toBe(false);
    expect(b.nodes.has('client:K2')).toBe(true);
    expect(b.nodes.has('certificate:A')).toBe(false);
    expect(b.nodes.has('dnsCredential:dns1')).toBe(false);
  });

  it('traces an issuer to its certificates and only their downstream', () => {
    const p = tracePath(flow, 'ca:ca2');
    expect(ids(p.nodes)).toEqual(['ca:ca2', 'certificate:B', 'channel:ch1', 'client:K2', 'client:K3', 'hook:H1', 'layout:L1']);
    expect(p.nodes.has('ca:ca1')).toBe(false);
    const shared = tracePath(flow, 'ca:ca1');
    expect(shared.nodes.has('certificate:A') && shared.nodes.has('certificate:B')).toBe(true);
    expect(shared.nodes.has('certificate:C')).toBe(false);
  });

  it('restricts a delivery node to its certificates and their paths through it', () => {
    const p = tracePath(flow, 'layout:L1');
    expect(p.nodes.has('hook:H1')).toBe(false);
    expect(p.nodes.has('client:K3')).toBe(false);
    expect(p.nodes.has('client:K1') && p.nodes.has('client:K2')).toBe(true);
    expect(p.nodes.has('certificate:C')).toBe(false);
    const h = tracePath(flow, 'hook:H1');
    expect(ids(h.nodes)).toEqual(['ca:ca1', 'ca:ca2', 'certificate:B', 'channel:ch1', 'client:K3', 'hook:H1']);
  });

  it('restricts a client to the certificates and delivery nodes that reach it', () => {
    const p = tracePath(flow, 'client:K1');
    expect(ids(p.nodes)).toEqual(['ca:ca1', 'certificate:A', 'channel:ch1', 'client:K1', 'dnsCredential:dns1', 'layout:L1']);
    const k2 = tracePath(flow, 'client:K2');
    expect(k2.nodes.has('certificate:A')).toBe(false);
    expect(k2.nodes.has('certificate:B')).toBe(true);
    expect(k2.nodes.has('hook:H1')).toBe(false);
  });

  it('covers every certificate from a covering channel and nothing from a non-covering one', () => {
    const p = tracePath(flow, 'channel:ch1');
    expect(ids(p.nodes)).toEqual(['certificate:A', 'certificate:B', 'certificate:C', 'channel:ch1']);
    expect(p.synthetic.size).toBe(3);
    const none = tracePath(flow, 'channel:ch2');
    expect(ids(none.nodes)).toEqual(['channel:ch2']);
  });

  it('follows direct certificate to client edges when the delivery lane is hidden', () => {
    const direct: Flow = {
      ...flow,
      lanes: { ...flow.lanes, delivery: lane([], true) },
      edges: [e('certificate:A', 'ca:ca1'), e('certificate:A', 'client:K1'), e('certificate:B', 'client:K2')],
    };
    const p = tracePath(direct, 'certificate:A');
    expect(p.nodes.has('client:K1')).toBe(true);
    expect(p.nodes.has('client:K2')).toBe(false);
    expect(ids(tracePath(direct, 'client:K1').nodes)).toEqual(['ca:ca1', 'certificate:A', 'channel:ch1', 'client:K1']);
  });
});

describe('channel links from delivery and client starts', () => {
  it('links covering channels to every traced certificate from a delivery node', () => {
    const p = tracePath(flow, 'layout:L1');
    expect(p.nodes.has('channel:ch1')).toBe(true);
    expect(p.nodes.has('channel:ch2')).toBe(false);
    expect(ids(p.synthetic)).toEqual([edgeKey('certificate:A', 'channel:ch1'), edgeKey('certificate:B', 'channel:ch1')]);
  });

  it('links covering channels to the certificates reaching a client', () => {
    const p = tracePath(flow, 'client:K2');
    expect(p.nodes.has('channel:ch1')).toBe(true);
    expect(ids(p.synthetic)).toEqual([edgeKey('certificate:B', 'channel:ch1')]);
  });
});

describe('pairStatus', () => {
  const dup = [
    { from: 'layout:L1', to: 'client:K1', status: 'valid' as const, certificateId: 'A' },
    { from: 'layout:L1', to: 'client:K1', status: 'failed' as const, certificateId: 'B' },
    { from: 'layout:L1', to: 'client:K1', status: 'drift' as const, certificateId: 'C' },
  ];
  it('uses the worst status with no selection', () => {
    expect(pairStatus(dup, null)).toBe('failed');
    expect(pairStatus(dup, new Set())).toBe('failed');
  });
  it('uses the status of the edge whose certificate is on the path', () => {
    expect(pairStatus(dup, new Set(['certificate:A']))).toBe('valid');
    expect(pairStatus(dup, new Set(['certificate:C', 'certificate:A']))).toBe('drift');
  });
  it('falls back to the worst status when no duplicate is on the path', () => {
    expect(pairStatus(dup, new Set(['certificate:Z']))).toBe('failed');
  });
});

describe('visibleNodeIds', () => {
  it('shows everything without filters', () => {
    expect(visibleNodeIds(flow, '  ', undefined)).toBeNull();
    expect(filterFlow(flow, null)).toBe(flow);
  });

  it('matches names case-insensitively and keeps the whole path of each match', () => {
    const v = visibleNodeIds(flow, 'k1', undefined)!;
    expect(ids(v)).toEqual(['ca:ca1', 'certificate:A', 'channel:ch1', 'client:K1', 'dnsCredential:dns1', 'layout:L1']);
  });

  it('problems keeps unhealthy nodes, nodes on a failing edge, and their paths', () => {
    const f: Flow = {
      ...flow,
      lanes: { ...flow.lanes, certificates: lane([node('certificate', 'A'), node('certificate', 'B'), node('certificate', 'C', { status: 'failed' })]) },
      edges: flow.edges.map((x) => (x.from === 'certificate:B' && x.to === 'ca:ca2' ? { ...x, status: 'failed' as const } : x)),
    };
    const v = visibleNodeIds(f, undefined, 'problems')!;
    expect(v.has('certificate:C')).toBe(true);
    expect(v.has('client:K2')).toBe(true);
    expect(v.has('ca:ca2')).toBe(true);
    expect(v.has('certificate:B')).toBe(true);
    expect(v.has('client:K1')).toBe(false);
    expect(v.has('certificate:A')).toBe(false);
    const g = filterFlow(f, v);
    expect(g.edges.every((x) => v.has(x.from) && v.has(x.to))).toBe(true);
    expect(g.lanes.clients.nodes.map((n) => n.name)).toEqual(['K2', 'K3']);
  });

  it('combines name and problems, and is empty when nothing matches', () => {
    expect(visibleNodeIds(flow, 'A', 'problems')!.size).toBe(0);
    expect(visibleNodeIds(flow, 'zzz', undefined)!.size).toBe(0);
  });
});

describe('collapseEdges', () => {
  const keyOf = (m: { a: string; b: string }) => `${m.a}>${m.b}`;

  it('returns one edge per node pair when nothing is collapsed', () => {
    const m = collapseEdges(flow, new Set());
    expect(m).toHaveLength(10);
    expect(m.find((x) => x.key === edgeKey('certificate:A', 'ca:ca1'))!.keys).toEqual([edgeKey('certificate:A', 'ca:ca1')]);
  });

  it('retargets a collapsed lane to its proxy and merges duplicates', () => {
    const m = collapseEdges(flow, new Set(['issuers']));
    const toIssuers = m.filter((x) => x.b === 'group:issuers' || x.a === 'group:issuers');
    // A and B each reach the issuers lane once, however many issuers they use.
    expect(toIssuers.map(keyOf).sort()).toEqual(['certificate:A>group:issuers', 'certificate:B>group:issuers']);
    const b = toIssuers.find((x) => x.a === 'certificate:B')!;
    expect(b.edges).toHaveLength(2);
    expect(b.keys.sort()).toEqual([edgeKey('certificate:B', 'ca:ca1'), edgeKey('certificate:B', 'ca:ca2')]);
  });

  it('carries the worst status of the merged edges', () => {
    const f: Flow = { ...flow, edges: flow.edges.map((x) => (x.to === 'ca:ca2' ? { ...x, status: 'expiring' as const } : x.to === 'ca:ca1' && x.from === 'certificate:B' ? { ...x, status: 'failed' as const } : x)) };
    expect(collapseEdges(f, new Set(['issuers.cas'])).find((x) => x.b === 'group:issuers.cas' && x.a === 'certificate:B')!.status).toBe('failed');
    const g: Flow = { ...flow, edges: flow.edges.map((x) => (x.to === 'ca:ca2' ? { ...x, status: 'expiring' as const } : x)) };
    expect(collapseEdges(g, new Set(['issuers'])).find((x) => x.a === 'certificate:B' && x.b === 'group:issuers')!.status).toBe('expiring');
  });

  it('drops edges whose two ends share a collapsed group, and collapses sub-groups on their own', () => {
    const f: Flow = { ...flow, edges: [...flow.edges, e('layout:L1', 'hook:H1')] };
    const m = collapseEdges(f, new Set(['delivery']));
    expect(m.some((x) => x.a === 'group:delivery' && x.b === 'group:delivery')).toBe(false);
    expect(m).toHaveLength(collapseEdges(flow, new Set(['delivery'])).length);
    const sub = collapseEdges(flow, new Set(['issuers.cas']));
    expect(sub.some((x) => x.b === 'dnsCredential:dns1' || x.a === 'dnsCredential:dns1')).toBe(true);
    expect(sub.some((x) => x.b === 'group:issuers.cas')).toBe(true);
  });

  it('retargets and dedupes the synthetic channel links', () => {
    const syn = [edgeKey('certificate:A', 'channel:ch1'), edgeKey('certificate:B', 'channel:ch1')];
    const m = collapseEdges(flow, new Set(['certificates', 'alerts']), syn);
    expect(m.filter((x) => x.synthetic).map((x) => x.key)).toEqual([`s:${edgeKey('group:certificates', 'group:alerts')}`]);
    const one = collapseEdges(flow, new Set(['alerts']), syn).filter((x) => x.synthetic);
    expect(one.map((x) => x.key).sort()).toEqual([`s:${edgeKey('certificate:A', 'group:alerts')}`, `s:${edgeKey('certificate:B', 'group:alerts')}`]);
    const both = collapseEdges(flow, new Set(['certificates']), syn).filter((x) => x.synthetic);
    expect(both).toHaveLength(1);
    expect(both[0]!.keys).toHaveLength(2);
  });
});
