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

type FlowIndex = {
  nodes: Map<string, FlowNodeData>;
  /** Edges touching each node id (either end). */
  adj: Map<string, FlowEdgeData[]>;
  channels: FlowNodeData[];
};

const indexes = new WeakMap<Flow, FlowIndex>();

/** Lookup maps built once per flow, so tracing a path never rescans the edge list. */
function indexOf(flow: Flow): FlowIndex {
  let ix = indexes.get(flow);
  if (ix) return ix;
  const nodes = new Map<string, FlowNodeData>();
  for (const k of LANE_KEYS) for (const n of flow.lanes[k].nodes) nodes.set(n.id, n);
  const adj = new Map<string, FlowEdgeData[]>();
  const push = (id: string, e: FlowEdgeData) => {
    const l = adj.get(id);
    if (l) l.push(e);
    else adj.set(id, [e]);
  };
  for (const e of flow.edges) {
    push(e.from, e);
    if (e.to !== e.from) push(e.to, e);
  }
  const channels = [...nodes.values()].filter((n) => n.kind === 'channel' && n.coversCertificates);
  ix = { nodes, adj, channels };
  indexes.set(flow, ix);
  return ix;
}

const NO_EDGES: FlowEdgeData[] = [];

/** Nodes and edges on the path through the selected node, upstream and
 * downstream. A delivery to client edge belongs to the one certificate named
 * by its certificateId, so a shared delivery node never cross-highlights. */
export function tracePath(flow: Flow, selectedId: string | null | undefined): FlowPath {
  const path: FlowPath = { nodes: new Set(), edges: new Set(), synthetic: new Set() };
  if (!selectedId) return path;
  const { nodes, adj, channels } = indexOf(flow);
  const sel = nodes.get(selectedId);
  if (!sel) return path;
  const edgesOf = (id: string) => adj.get(id) ?? NO_EDGES;
  const lane = (id: string): LaneKey | undefined => {
    const n = nodes.get(id);
    return n ? laneOf(n.kind) : undefined;
  };

  const add = (a: string, b: string) => {
    path.nodes.add(a);
    path.nodes.add(b);
    path.edges.add(edgeKey(a, b));
  };
  const carries = (e: Flow['edges'][number], cid: string) => !e.certificateId || e.certificateId === cid;

  const certPath = (cert: string, o: Opts) => {
    path.nodes.add(cert);
    const cid = rawId(cert);
    for (const e of edgesOf(cert)) {
      const other = e.from === cert ? e.to : e.to === cert ? e.from : null;
      if (other === null || !nodes.has(other)) continue;
      const l = lane(other);
      if (l === 'issuers' && (!o.issuer || o.issuer === other)) add(cert, other);
      else if (l === 'delivery' && (!o.delivery || o.delivery === other)) {
        const via = edgesOf(other).filter((d) => d.from === other && lane(d.to) === 'clients' && carries(d, cid) && (!o.client || o.client === d.to));
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
    for (const e of edgesOf(id)) {
      const other = e.from === id ? e.to : e.to === id ? e.from : null;
      if (other && lane(other) === 'certificates') out.add(other);
    }
    if (lane(id) === 'clients') {
      // A client behind a delivery node belongs to the certificates that use that node.
      for (const e of edgesOf(id)) {
        if (e.to !== id || lane(e.from) !== 'delivery') continue;
        for (const c of edgesOf(e.from)) {
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

/** Needs attention: pending is transitional and healthy/idle are fine. */
export const isProblem = (s: FlowStatus): boolean => s === 'failed' || s === 'expired' || s === 'drift' || s === 'expiring';

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

export type SubGroup = { id: string; title: string; kinds: FlowNodeData['kind'][] };

/** Lanes that split into headed sub-groups; each id is `<lane>.<name>`. */
export const SUBGROUPS: Partial<Record<LaneKey, SubGroup[]>> = {
  issuers: [
    { id: 'issuers.cas', title: 'CAs', kinds: ['ca'] },
    { id: 'issuers.accounts', title: 'ACME accounts', kinds: ['account'] },
    { id: 'issuers.dns', title: 'DNS credentials', kinds: ['dnsCredential'] },
  ],
  delivery: [
    { id: 'delivery.layouts', title: 'Layouts', kinds: ['layout'] },
    { id: 'delivery.targets', title: 'Targets', kinds: ['target'] },
    { id: 'delivery.hooks', title: 'Hooks', kinds: ['hook'] },
  ],
};

/** Element id of the proxy row standing in for a collapsed group. */
export const proxyId = (groupId: string): string => `group:${groupId}`;
export const isProxyId = (id: string): boolean => id.startsWith('group:');
/** Lane index of a node id or proxy id the connectors draw to. */
export const proxyLaneIndex = (id: string): number => LANE_KEYS.indexOf(id.slice('group:'.length).split('.')[0] as LaneKey);

/** The outermost collapsed group holding a node of this kind, if any. */
export function collapsedGroupOf(kind: FlowNodeData['kind'], collapsed: Set<string>): string | undefined {
  const lane = laneOf(kind);
  if (collapsed.has(lane)) return lane;
  const sub = SUBGROUPS[lane]?.find((g) => g.kinds.includes(kind));
  return sub && collapsed.has(sub.id) ? sub.id : undefined;
}

/** `collapsed` without the lane and sub-group holding a node of this kind. */
export function expandFor(kind: FlowNodeData['kind'], collapsed: string[]): string[] {
  const lane = laneOf(kind);
  const sub = SUBGROUPS[lane]?.find((g) => g.kinds.includes(kind))?.id;
  return collapsed.filter((g) => g !== lane && g !== sub);
}

/** The worst of several statuses (failed > expired > drift > expiring > pending > valid > idle). */
export function worstStatus(statuses: FlowStatus[]): FlowStatus {
  return statuses.reduce<FlowStatus>((w, s) => (SEVERITY.indexOf(s) < SEVERITY.indexOf(w) ? s : w), 'idle');
}

export type MergedEdge = {
  key: string;
  a: string;
  b: string;
  /** A client-drawn certificate to channel link. */
  synthetic: boolean;
  /** Worst status among the merged edges; null when synthetic. */
  status: FlowStatus | null;
  /** The real edges merged into this one. */
  edges: FlowEdgeData[];
  /** edgeKey()s of the original (pre-retarget) node pairs and links. */
  keys: string[];
};

/** Rewrites the graph for rendering with some groups collapsed: an edge end
 * inside a collapsed group moves to that group's proxy, edges that then run
 * between the same two ends merge (worst status wins), and edges inside one
 * collapsed group disappear. Synthetic channel links get the same treatment. */
export function collapseEdges(flow: Flow, collapsed: Set<string>, synthetic: Iterable<string> = []): MergedEdge[] {
  const kinds = new Map<string, FlowNodeData['kind']>();
  for (const k of LANE_KEYS) for (const n of flow.lanes[k].nodes) kinds.set(n.id, n.kind);
  const target = (id: string): string => {
    const kind = kinds.get(id);
    const g = kind && collapsedGroupOf(kind, collapsed);
    return g ? proxyId(g) : id;
  };
  const out = new Map<string, MergedEdge>();
  const seen = new Map<string, Set<string>>();
  const put = (a: string, b: string, key: string, orig: string, isSynthetic: boolean, edge?: FlowEdgeData) => {
    if (a === b) return;
    let m = out.get(key);
    let origs = seen.get(key);
    if (!m || !origs) {
      m = { key, a, b, synthetic: isSynthetic, status: null, edges: [], keys: [] };
      origs = new Set();
      out.set(key, m);
      seen.set(key, origs);
    }
    if (!origs.has(orig)) {
      origs.add(orig);
      m.keys.push(orig);
    }
    if (edge) {
      m.edges.push(edge);
      if (m.status === null || SEVERITY.indexOf(edge.status) < SEVERITY.indexOf(m.status)) m.status = edge.status;
    }
  };
  for (const e of flow.edges) {
    const a = target(e.from);
    const b = target(e.to);
    put(a, b, edgeKey(a, b), edgeKey(e.from, e.to), false, e);
  }
  for (const k of synthetic) {
    const [x, y] = k.split('|');
    if (!x || !y) continue;
    const a = target(x);
    const b = target(y);
    put(a, b, `s:${edgeKey(a, b)}`, k, true);
  }
  return [...out.values()];
}
