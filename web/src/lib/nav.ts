import { Bell, Gauge, Landmark, ScrollText, Server, Settings, ShieldCheck, Truck, type LucideIcon } from 'lucide-react';

export type NavTarget = 'overview' | 'certificates' | 'issuers' | 'settings';
export type NavItem = { label: string; icon: LucideIcon; target?: NavTarget };

export const LATER = 'Available in a later phase';

// Spec "Web UI design" navigation table: three groups, eight items. Phase 1
// enables Overview, Certificates, Issuers, and Settings (`target` set);
// the rest render disabled with the LATER tooltip, never hidden.
export const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: 'Operate',
    items: [
      { label: 'Overview', icon: Gauge, target: 'overview' },
      { label: 'Certificates', icon: ShieldCheck, target: 'certificates' },
      { label: 'Clients', icon: Server },
    ],
  },
  {
    group: 'Configure',
    items: [
      { label: 'Issuers', icon: Landmark, target: 'issuers' },
      { label: 'Delivery', icon: Truck },
      { label: 'Alerts', icon: Bell },
    ],
  },
  {
    group: 'Govern',
    items: [
      { label: 'Audit log', icon: ScrollText },
      { label: 'Settings', icon: Settings, target: 'settings' },
    ],
  },
];

export function navPrefix(target: NavTarget, org: string): string {
  return target === 'settings' ? '/settings' : `/o/${org}/${target}`;
}
