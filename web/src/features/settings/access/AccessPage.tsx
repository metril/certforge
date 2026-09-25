import type { ReactNode } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { EmptyState } from '@/components/EmptyState';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useMe } from '@/lib/org';
import { canAnywhere, type Action } from '@/lib/permissions';
import type { AccessTab, SettingsSearch } from '../sections';
import { ApiKeysTab } from './ApiKeysTab';
import { BindingsTab } from './BindingsTab';
import { UsersTab } from './UsersTab';

const TABS: { value: AccessTab; label: string; action: Action; render: () => ReactNode }[] = [
  { value: 'users', label: 'Users', action: 'users:read', render: () => <UsersTab /> },
  { value: 'bindings', label: 'Role bindings', action: 'bindings:read', render: () => <BindingsTab /> },
  { value: 'keys', label: 'API keys', action: 'apikeys:read', render: () => <ApiKeysTab /> },
];

// Controller ruling: `q` is a per-tab filter, so switching tabs drops it
// instead of carrying the previous tab's search term along. Exported as a
// plain function (rather than inlined in `onValueChange`) so it's testable
// without depending on Radix Tabs only calling `onValueChange` when the
// clicked trigger differs from the currently-selected one.
export function onTabChange(prev: SettingsSearch, v: AccessTab): SettingsSearch {
  return { ...prev, tab: v, q: undefined };
}

export function AccessPage() {
  const me = useMe();
  const search = useSearch({ from: '/_app/settings/$section' });
  const navigate = useNavigate({ from: '/settings/$section' });
  const tabs = TABS.filter((t) => canAnywhere(me, t.action));
  if (tabs.length === 0) return <EmptyState message="Your role has no access here." />;
  const current = tabs.find((t) => t.value === search.tab)?.value ?? tabs[0]!.value;
  return (
    <Tabs value={current} onValueChange={(v) => void navigate({ search: (prev) => onTabChange(prev, v as AccessTab), replace: true })}>
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
