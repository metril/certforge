import { Bell, Gauge, Landmark, ScrollText, Server, Settings, ShieldCheck, Truck, Workflow, type LucideIcon } from 'lucide-react';

export type NavTarget = 'overview' | 'flow' | 'certificates' | 'clients' | 'issuers' | 'delivery' | 'alerts' | 'audit' | 'settings';
export type NavItem = { label: string; icon: LucideIcon; target?: NavTarget };

export const LATER = 'Available in a later phase';
export const NO_ORG = 'No organization exists yet.';
export const NO_AUDIT = 'Needs the auditor or an admin role.';

// Targets that resolve under /o/$org/...; Settings does not need an org.
export function targetNeedsOrg(target: NavTarget): boolean {
  return target !== 'settings';
}

// Spec "Web UI design" navigation table: three groups, eight items. Phase 1
// enabled Overview, Certificates, Issuers, and Settings; Phase 2B added
// Audit log; Phase 3B added Clients and Delivery (`target` set on each);
// 6B Task 2 enables Alerts.
export const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: 'Operate',
    items: [
      { label: 'Overview', icon: Gauge, target: 'overview' },
      { label: 'Flow', icon: Workflow, target: 'flow' },
      { label: 'Certificates', icon: ShieldCheck, target: 'certificates' },
      { label: 'Clients', icon: Server, target: 'clients' },
    ],
  },
  {
    group: 'Configure',
    items: [
      { label: 'Issuers', icon: Landmark, target: 'issuers' },
      { label: 'Delivery', icon: Truck, target: 'delivery' },
      { label: 'Alerts', icon: Bell, target: 'alerts' },
    ],
  },
  {
    group: 'Govern',
    items: [
      { label: 'Audit log', icon: ScrollText, target: 'audit' },
      { label: 'Settings', icon: Settings, target: 'settings' },
    ],
  },
];

export function navPrefix(target: NavTarget, org: string): string {
  return target === 'settings' ? '/settings' : `/o/${org}/${target}`;
}

// Segment-boundary-aware match (mirrors TanStack Router's own Link active-
// state algorithm): a raw `pathname.startsWith(prefix)` also lights up
// "/o/acme/certificates-foo" for the Certificates item. This also lets one
// nav item (e.g. Settings) stay active across every child path
// ("/settings/tls" still highlights Settings), which a literal resolved
// href match cannot do.
export function isNavPathActive(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

// Nav targets that stay usable under /o/all/... (the read-only All orgs
// view); the rest (Issuers, and later Delivery/Alerts) redirect on
// navigation (lib/org.ts's denyAllOrgs) and are shown disabled here with
// ALL_ORGS_ONLY_ONE instead of navigating.
export const ALL_ORGS_TARGETS: ReadonlySet<NavTarget> = new Set(['overview', 'certificates', 'clients', 'audit', 'settings']);
export const ALL_ORGS_ONLY_ONE = 'Pick one organization';

// Visible label of the read-only banner shown on every /o/all/... page
// (components/ReadOnlyBanner.tsx).
export const ALL_ORGS_BANNER = 'All orgs · read-only';
