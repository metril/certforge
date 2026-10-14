import type { ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Link, useMatch, useNavigate, useParams, useRouter, type LinkProps } from '@tanstack/react-router';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { grantsListQuery } from '@/api/queries/grants';
import type { Grant } from '@/api/types';
import type { Me } from '@/api/types';
import { cn } from '@/lib/utils';
import { useOrgSlugOf } from '@/lib/org';
import { can, canAnywhere, type Action } from '@/lib/permissions';

export type EntityKind =
  | 'certificate'
  | 'client'
  | 'ca'
  | 'acmeAccount'
  | 'dnsCredential'
  | 'target'
  | 'layout'
  | 'action'
  | 'actionGroup'
  | 'deployCredential'
  | 'monitor'
  | 'channel'
  | 'user'
  | 'apiKey'
  | 'site'
  | 'grant';

/** The audit log's resourceType for each kind that has a destination. */
export const RESOURCE_KIND: Record<string, EntityKind> = {
  certificate: 'certificate',
  client: 'client',
  ca: 'ca',
  acme_account: 'acmeAccount',
  dns_credential: 'dnsCredential',
  deploy_target: 'target',
  layout: 'layout',
  action: 'action',
  action_group: 'actionGroup',
  deploy_credential: 'deployCredential',
  monitor: 'monitor',
  channel: 'channel',
  user: 'user',
  api_key: 'apiKey',
  site: 'site',
  grant: 'grant',
};

/** A router destination, built untyped so one table can cover every route. */
export type Target = { to: string; params?: Record<string, string>; search?: Record<string, string> };

const READ: Record<Exclude<EntityKind, 'user' | 'apiKey'>, Action> = {
  certificate: 'certs:read',
  client: 'clients:read',
  ca: 'cas:read',
  acmeAccount: 'accounts:read',
  dnsCredential: 'dnscreds:read',
  target: 'delivery:read',
  layout: 'delivery:read',
  action: 'delivery:read',
  actionGroup: 'delivery:read',
  deployCredential: 'deploycreds:read',
  monitor: 'alerts:read',
  channel: 'alerts:read',
  site: 'sites:read',
  grant: 'clients:read',
};

/** Where a (non-grant) entity lives. */
export function entityTarget(kind: Exclude<EntityKind, 'grant'>, id: string, org: string): Target {
  const p = { org, id };
  switch (kind) {
    case 'certificate':
      return { to: '/o/$org/certificates/$id/$tab', params: { ...p, tab: 'overview' } };
    case 'client':
      return { to: '/o/$org/clients/$id/$tab', params: { ...p, tab: 'certificates' } };
    case 'ca':
      return { to: '/o/$org/issuers/cas/$id/$tab', params: { ...p, tab: 'overview' } };
    case 'acmeAccount':
      // Accounts have no sheet to open, so this lands on the list.
      return { to: '/o/$org/issuers/accounts', params: { org } };
    case 'dnsCredential':
      return { to: '/o/$org/issuers/dns', params: { org }, search: { edit: id } };
    case 'target':
      return { to: '/o/$org/delivery/targets/$id/$tab', params: { ...p, tab: 'overview' } };
    case 'layout':
      return { to: '/o/$org/delivery/layouts/$id/edit', params: p };
    case 'action':
      return { to: '/o/$org/delivery/actions', params: { org }, search: { tab: 'actions', edit: id } };
    case 'actionGroup':
      return { to: '/o/$org/delivery/actions', params: { org }, search: { tab: 'groups', edit: id } };
    case 'deployCredential':
      return { to: '/o/$org/delivery/credentials', params: { org }, search: { edit: id } };
    case 'monitor':
      return { to: '/o/$org/alerts/monitors/$id/edit', params: p };
    case 'channel':
      return { to: '/o/$org/alerts/channels', params: { org }, search: { edit: id } };
    case 'site':
      // Sites have no page: Settings > General opens the org's Sites sheet on this one.
      return { to: '/settings/$section', params: { section: 'general' }, search: { org, site: id } };
    case 'user':
      // Users and API keys are listed, not opened: land on the right tab.
      return { to: '/settings/$section', params: { section: 'access' }, search: { tab: 'users' } };
    case 'apiKey':
      return { to: '/settings/$section', params: { section: 'access' }, search: { tab: 'keys' } };
  }
}

/** A server grant opens on its target's Grants tab, an agent grant on its client's Certificates tab. */
export function grantTarget(g: Pick<Grant, 'id' | 'runsOn' | 'deployTargetId' | 'clientId'>, org: string): Target | null {
  if (g.runsOn === 'server' && g.deployTargetId) return { to: '/o/$org/delivery/targets/$id/$tab', params: { org, id: g.deployTargetId, tab: 'grants' }, search: { open: g.id } };
  if (g.clientId) return { to: '/o/$org/clients/$id/$tab', params: { org, id: g.clientId, tab: 'certificates' }, search: { open: g.id } };
  return null;
}

const linkCls = 'rounded-sm underline-offset-2 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring';

function GrantLink({ id, orgId, children, className }: { id: string; orgId: string; children: ReactNode; className?: string }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const slugOf = useOrgSlugOf();
  // The grant's own row says whether it lives on a client or a target, so look it up on click.
  const go = async () => {
    try {
      const [g] = await qc.fetchQuery(grantsListQuery(orgId, { grantId: id }));
      const t = g && grantTarget(g, slugOf(orgId));
      if (!t) return void toast.error('Grant not found.');
      void navigate(t as LinkProps);
    } catch (e) {
      toast.error(`Couldn't open the grant. ${errorMessage(e)}`);
    }
  };
  return (
    <button type="button" className={cn(linkCls, className)} onClick={() => void go()}>
      {children}
    </button>
  );
}

/**
 * A link to the object a record refers to. Plain text when the id is empty,
 * the kind has no destination, or the viewer cannot read the target.
 */
type Props = { kind: EntityKind; id: string | null | undefined; orgId?: string | null; className?: string; children: ReactNode };

export function EntityLink(props: Props) {
  // Rendered outside a router (a bare component test) there is nothing to link within.
  const router = useRouter({ warn: false });
  if (!router || !props.id) return <>{props.children}</>;
  return <InApp {...props} />;
}

function InApp(props: Props) {
  const app = useMatch({ from: '/_app', shouldThrow: false });
  if (!app) return <>{props.children}</>;
  return <Resolved {...props} me={app.context.me} />;
}

function Resolved({ kind, id, orgId, className, children, me }: Props & { me: Me }) {
  const slugOf = useOrgSlugOf();
  // Outside an org route (Settings) the caller names the org; under All orgs there is none.
  const { org: slug } = useParams({ strict: false }) as { org?: string };
  const scopeId = orgId ?? me.orgs.find((o) => o.slug === slug)?.id;
  if (!id) return <>{children}</>;
  if (kind === 'user' || kind === 'apiKey') {
    if (!canAnywhere(me, kind === 'user' ? 'users:read' : 'apikeys:read')) return <>{children}</>;
    return (
      <Link {...(entityTarget(kind, id, '') as LinkProps)} className={cn(linkCls, className)}>
        {children}
      </Link>
    );
  }
  if (!scopeId || !can(me, READ[kind], scopeId)) return <>{children}</>;
  if (kind === 'grant')
    return (
      <GrantLink id={id} orgId={scopeId} className={className}>
        {children}
      </GrantLink>
    );
  return (
    <Link {...(entityTarget(kind, id, slugOf(scopeId)) as LinkProps)} className={cn(linkCls, className)}>
      {children}
    </Link>
  );
}
