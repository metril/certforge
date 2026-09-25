import type { ReactNode } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { EmptyState } from '@/components/EmptyState';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useMe } from '@/lib/org';
import { canAnywhere, type Action } from '@/lib/permissions';
import type { AccessTab } from '../sections';
import { UsersTab } from './UsersTab';

// Tasks 4 and 6 append the bindings and keys tabs here.
const TABS: { value: AccessTab; label: string; action: Action; render: () => ReactNode }[] = [
  { value: 'users', label: 'Users', action: 'users:read', render: () => <UsersTab /> },
];

export function AccessPage() {
  const me = useMe();
  const search = useSearch({ from: '/_app/settings/$section' });
  const navigate = useNavigate({ from: '/settings/$section' });
  const tabs = TABS.filter((t) => canAnywhere(me, t.action));
  if (tabs.length === 0) return <EmptyState message="Your role has no access here." />;
  const current = tabs.find((t) => t.value === search.tab)?.value ?? tabs[0]!.value;
  return (
    <Tabs value={current} onValueChange={(v) => void navigate({ search: (prev) => ({ ...prev, tab: v as AccessTab }), replace: true })}>
      <TabsList>
        {tabs.map((t) => (
          <TabsTrigger key={t.value} value={t.value}>
            {t.label}
          </TabsTrigger>
        ))}
      </TabsList>
      {tabs.map((t) => (
        <TabsContent key={t.value} value={t.value} className="pt-4">
          {t.render()}
        </TabsContent>
      ))}
    </Tabs>
  );
}
