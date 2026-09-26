import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { errorMessage } from '@/api/errors';
import { clientQuery } from '@/api/queries/clients';
import { sitesQuery } from '@/api/queries/sites';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { ClientHeader } from './ClientHeader';
import { GrantsTab } from './GrantsTab';
import { SettingsTab } from './SettingsTab';
import { CLIENT_TAB_LABEL, CLIENT_TABS, type ClientTab } from './tabs';

export function ClientDetail({ id, tab }: { id: string; tab: ClientTab }) {
  const org = useOrg();
  const me = useMe();
  const navigate = useNavigate();
  const search = useSearch({ from: '/_app/o/$org/clients/$id/$tab' });
  const { data: client, isPending, error } = useQuery(clientQuery(org.id, id));
  const { data: sites = [] } = useQuery(sitesQuery(org.id));
  if (isPending) return <p className="text-ink-muted">Loading…</p>;
  if (error) return <p role="alert">{errorMessage(error)}</p>;
  const canWrite = can(me, 'clients:write', org.id);
  const siteName = sites.find((s) => s.id === client.siteId)?.name;
  const goTab = (t: ClientTab) => void navigate({ to: '/o/$org/clients/$id/$tab', params: { org: org.slug, id, tab: t }, search: {} });
  const setOpen = (open: string | undefined) =>
    void navigate({ to: '/o/$org/clients/$id/$tab', params: { org: org.slug, id, tab }, search: (prev) => ({ ...prev, open }), replace: true });

  return (
    <div className="grid gap-6">
      <nav aria-label="Breadcrumb" className="text-sm">
        <Link to="/o/$org/clients" params={{ org: org.slug }} className="text-ink-muted hover:text-ink">
          Clients
        </Link>
      </nav>
      <ClientHeader client={client} siteName={siteName} />
      <Tabs value={tab} onValueChange={(v) => goTab(v as ClientTab)}>
        <TabsList className="max-w-full overflow-x-auto">
          {CLIENT_TABS.map((t) => (
            <TabsTrigger key={t} value={t}>
              {CLIENT_TAB_LABEL[t]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="certificates" className="pt-4">
          <GrantsTab client={client} orgId={org.id} orgSlug={org.slug} canWrite={canWrite} open={search.open} onOpen={setOpen} />
        </TabsContent>
        <TabsContent value="settings" className="pt-4">
          {/* key: a refetched name/site resets the form after a save elsewhere */}
          <SettingsTab key={`${client.name}:${client.siteId}`} client={client} orgId={org.id} orgSlug={org.slug} sites={sites} canWrite={canWrite} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
