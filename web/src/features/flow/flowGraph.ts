import type { components } from '@/api/schema';

export type Flow = components['schemas']['Flow'];
export type FlowNodeData = components['schemas']['FlowNode'];
export type FlowEdgeData = components['schemas']['FlowEdge'];
export type FlowStatus = components['schemas']['FlowStatus'];

export const LANE_KEYS = ['issuers', 'certificates', 'delivery', 'clients', 'alerts'] as const;
export type LaneKey = (typeof LANE_KEYS)[number];

const KIND_LANE: Record<FlowNodeData['kind'], LaneKey> = {
  ca: 'issuers',
  account: 'issuers',
  dnsCredential: 'issuers',
  certificate: 'certificates',
  layout: 'delivery',
  target: 'delivery',
  hook: 'delivery',
  client: 'clients',
  channel: 'alerts',
};

export const laneOf = (kind: FlowNodeData['kind']): LaneKey => KIND_LANE[kind];

export const laneIndex = (kind: FlowNodeData['kind']): number => LANE_KEYS.indexOf(KIND_LANE[kind]);

/** Order-independent key for the connection between two nodes. */
export const edgeKey = (a: string, b: string): string => (a < b ? `${a}|${b}` : `${b}|${a}`);

export type FlowPath = {
  /** Node ids on the path (including the selected node). */
  nodes: Set<string>;
  /** edgeKey()s of real edges on the path. */
  edges: Set<string>;
  /** edgeKey()s of the certificate to channel links the client draws itself. */
  synthetic: Set<string>;
};

const rawId = (id: string): string => id.slice(id.indexOf(':') + 1);

type Opts = { issuer?: string; delivery?: string; client?: string };

/** Nodes and edges on the path through the selected node, upstream and
 * downstream. A delivery to client edge belongs to the one certificate named
 * by its certificateId, so a shared delivery node never cross-highlights. */
export function tracePath(flow: Flow, selectedId: string | null | undefined): FlowPath {
  const path: FlowPath = { nodes: new Set(), edges: new Set(), synthetic: new Set() };
  if (!selectedId) return path;
  const nodes = new Map<string, FlowNodeData>();
  for (const k of LANE_KEYS) for (const n of flow.lanes[k].nodes) nodes.set(n.id, n);
  const sel = nodes.get(selectedId);
  if (!sel) return path;
  const lane = (id: string): LaneKey | undefined => {
    const n = nodes.get(id);
    return n ? laneOf(n.kind) : undefined;
  };
  const channels = [...nodes.values()].filter((n) => n.kind === 'channel' && n.coversCertificates);

  const add = (a: string, b: string) => {
    path.nodes.add(a);
    path.nodes.add(b);
    path.edges.add(edgeKey(a, b));
  };
  const carries = (e: Flow['edges'][number], cid: string) => !e.certificateId || e.certificateId === cid;

  const certPath = (cert: string, o: Opts) => {
    path.nodes.add(cert);
    const cid = rawId(cert);
    for (const e of flow.edges) {
      const other = e.from === cert ? e.to : e.to === cert ? e.from : null;
      if (other === null || !nodes.has(other)) continue;
      const l = lane(other);
      if (l === 'issuers' && (!o.issuer || o.issuer === other)) add(cert, other);
      else if (l === 'delivery' && (!o.delivery || o.delivery === other)) {
        const via = flow.edges.filter((d) => d.from === other && lane(d.to) === 'clients' && carries(d, cid) && (!o.client || o.client === d.to));
        if (o.client && via.length === 0) continue;
        add(cert, other);
        for (const d of via) add(other, d.to);
      } else if (l === 'clients' && !o.delivery && (!o.client || o.client === other)) {
        // Direct certificate to client link: the delivery lane is absent.
        add(cert, other);
      }
    }
  };

  const certsOf = (id: string): string[] => {
    const out = new Set<string>();
    for (const e of flow.edges) {
      const other = e.from === id ? e.to : e.to === id ? e.from : null;
      if (other && lane(other) === 'certificates') out.add(other);
    }
    if (lane(id) === 'clients') {
      // A client behind a delivery node belongs to the certificates that use that node.
      for (const e of flow.edges) {
        if (e.to !== id || lane(e.from) !== 'delivery') continue;
        for (const c of flow.edges) {
          if (c.to === e.from && lane(c.from) === 'certificates' && carries(e, rawId(c.from))) out.add(c.from);
        }
      }
    }
    return [...out];
  };

  const link = (cert: string) => {
    for (const ch of channels) {
      path.nodes.add(ch.id);
      path.synthetic.add(edgeKey(cert, ch.id));
    }
  };

  path.nodes.add(sel.id);
  switch (laneOf(sel.kind)) {
    case 'certificates':
      certPath(sel.id, {});
      link(sel.id);
      break;
    case 'issuers':
      for (const c of certsOf(sel.id)) {
        certPath(c, { issuer: sel.id });
        link(c);
      }
      break;
    case 'delivery':
      for (const c of certsOf(sel.id)) {
        certPath(c, { delivery: sel.id });
        link(c);
      }
      break;
    case 'clients':
      for (const c of certsOf(sel.id)) {
        certPath(c, { client: sel.id });
        link(c);
      }
      break;
    case 'alerts':
      if (sel.coversCertificates) {
        for (const n of nodes.values()) {
          if (n.kind !== 'certificate') continue;
          path.nodes.add(n.id);
          path.synthetic.add(edgeKey(n.id, sel.id));
        }
      }
      break;
  }
  return path;
}

const SEVERITY: FlowStatus[] = ['failed', 'expired', 'drift', 'expiring', 'pending', 'valid', 'idle'];

/** One status for the duplicate edges drawn between the same two nodes (a
 * delivery to client edge exists once per certificate). With a selection,
 * the status of an edge whose certificate is on the path wins; otherwise the
 * worst status among them. */
export function pairStatus(edges: FlowEdgeData[], pathNodes?: Set<string> | null): FlowStatus {
  const onPath = pathNodes && pathNodes.size > 0 ? edges.filter((e) => e.certificateId && pathNodes.has(`certificate:${e.certificateId}`)) : [];
  const pool = onPath.length > 0 ? onPath : edges;
  return pool.reduce((w, e) => (SEVERITY.indexOf(e.status) < SEVERITY.indexOf(w) ? e.status : w), pool[0]!.status);
}

const isProblem = (s: FlowStatus): boolean => s !== 'valid' && s !== 'idle';

/** Ids of the nodes to draw under the `q` / `problems` filters, or null when
 * no filter is active. A node is kept when it matches or lies on the path of
 * a matching node, so every surviving flow stays whole end to end. */
export function visibleNodeIds(flow: Flow, q: string | undefined, status: 'problems' | undefined): Set<string> | null {
  const needle = (q ?? '').trim().toLowerCase();
  if (!needle && !status) return null;
  const touched = new Set<string>();
  if (status) {
    for (const e of flow.edges) {
      if (!isProblem(e.status)) continue;
      touched.add(e.from);
      touched.add(e.to);
    }
  }
  const keep = new Set<string>();
  for (const k of LANE_KEYS) {
    for (const n of flow.lanes[k].nodes) {
      if (needle && !n.name.toLowerCase().includes(needle)) continue;
      if (status && !isProblem(n.status) && !touched.has(n.id)) continue;
      keep.add(n.id);
      for (const id of tracePath(flow, n.id).nodes) keep.add(id);
    }
  }
  return keep;
}

/** The flow restricted to `visible` nodes; edges with a hidden end are dropped. */
export function filterFlow(flow: Flow, visible: Set<string> | null): Flow {
  if (!visible) return flow;
  const lanes = { ...flow.lanes };
  for (const k of LANE_KEYS) lanes[k] = { ...flow.lanes[k], nodes: flow.lanes[k].nodes.filter((n) => visible.has(n.id)) };
  return { ...flow, lanes, edges: flow.edges.filter((e) => visible.has(e.from) && visible.has(e.to)) };
}
