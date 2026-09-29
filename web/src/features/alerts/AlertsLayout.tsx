import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { HelpTip } from '@/components/HelpTip';
import { PageHeader } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK } from '@/components/TabLabel';
import { useOrg } from '@/lib/org';

const ALERTS_TABS = [
  { to: '/o/$org/alerts/channels', label: 'Channels', help: 'alerts.channels' },
  { to: '/o/$org/alerts/monitors', label: 'Monitors', help: 'alerts.monitors' },
  { to: '/o/$org/alerts/events', label: 'Events', help: 'alerts.events' },
] as const;

export function AlertsLayout({ children }: { children: ReactNode }) {
  const { slug: org } = useOrg();
  return (
    <>
      <PageHeader title="Alerts" />
      <nav aria-label="Alerts" className="mb-6 flex gap-6 overflow-x-auto border-b border-border">
        {ALERTS_TABS.map((t) => (
          // A HelpTip's own <button> cannot nest inside the tab <a> (invalid
          // HTML), so it sits beside the Link, not inside it.
          <span key={t.to} className="inline-flex shrink-0 items-center gap-1">
            <Link to={t.to} params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE}>
              {t.label}
            </Link>
            <HelpTip id={t.help} />
          </span>
        ))}
      </nav>
      {children}
    </>
  );
}
