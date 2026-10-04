import { useEffect, useState } from 'react';
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { FileText, FolderInput, Plus, RotateCw, Server, ShieldCheck, Upload } from 'lucide-react';
import { runBackup } from '@/api/queries/backup';
import { certificateSearchQuery, useRenewCertificates } from '@/api/queries/certificates';
import { allClientsQuery } from '@/api/queries/clients';
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { ALL_ORGS_SLUG, useMe, useOrgSlugOf } from '@/lib/org';
import { can, canAnywhere } from '@/lib/permissions';
import { renewToastHandlers } from '@/lib/renewToast';
import { keywordFilter } from '@/lib/utils';

/**
 * Ctrl/Cmd-K palette: jump to a certificate by any name or a client by name
 * or hostname, jump to a page, or run New certificate, Enrol client, Renew
 * <name>. Every
 * `CommandItem` gets a `value` prefixed with its kind (`page:`, `cert:`,
 * `action:`, `renew:`) plus its own id, so two entries never collide on
 * cmdk's own value-based selection even when a page label and a
 * certificate name happen to match.
 *
 * The dialog itself carries the `cf-command-palette` class so
 * `lib/shortcuts.ts` can exempt this specific dialog (not dialogs in
 * general) from its own suppress selector: without that, a second
 * Ctrl/Cmd-K pressed while the search input has focus — inside a
 * `[role="dialog"]`, which normally suppresses shortcuts — would never
 * reach `onOpenPalette`, and the palette could only be opened, never
 * closed the same way.
 */
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const me = useMe();
  const params = useParams({ strict: false }) as { org?: string };
  const allOrgs = params.org === ALL_ORGS_SLUG;
  // No org (a fresh account with none yet, or /settings/*), and All orgs
  // (ruling A3): certificate search, New certificate, Renew, and the
  // org-scoped pages below (Issuers…) are left out, matching Sidebar's own
  // "disabled without an org"/"All orgs restricted" treatment (lib/nav.ts's
  // NO_ORG/ALL_ORGS_TARGETS). Under All orgs `org` is `undefined` rather
  // than falling back to `me.orgs[0]` — a global admin who never picked an
  // org must not be able to renew or create in one they didn't choose.
  const org = allOrgs ? undefined : (me.orgs.find((o) => o.slug === params.org) ?? me.orgs[0]);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const canSettingsWrite = can(me, 'settings:write');
  const renew = useRenewCertificates(org?.id ?? '');
  // Fix round 2 (Important #1): entries the caller can't act on or read are
  // left out, mirroring Sidebar's own per-item gating (audit) and
  // SettingsPage's own section filter (access), rather than relying on the
  // API to 403 after the fact.
  const canCreate = !!org && can(me, 'certs:write', org.id);
  const canIssue = !!org && can(me, 'certs:issue', org.id);
  const canReadCerts = !!org && can(me, 'certs:read', org.id);
  const canReadCas = !!org && can(me, 'cas:read', org.id);
  const canReadAccounts = !!org && can(me, 'accounts:read', org.id);
  const canReadDnsCreds = !!org && can(me, 'dnscreds:read', org.id);
  const canReadAudit = allOrgs ? canAnywhere(me, 'audit:read') : !!org && can(me, 'audit:read', org.id);
  const canReadUsers = canAnywhere(me, 'users:read');
  const canReadClients = allOrgs ? canAnywhere(me, 'clients:read') : !!org && can(me, 'clients:read', org.id);
  const canWriteClients = !!org && can(me, 'clients:write', org.id);
  const canReadDelivery = !!org && can(me, 'delivery:read', org.id);
  const canReadAlerts = !!org && can(me, 'alerts:read', org.id);
  // M7: under All orgs there's no single org to scope the request to, but the
  // GET /clients cross-org listing (already used by the clients list's own
  // All orgs view) covers it — read-only navigation only, matching every
  // other All orgs entry point here.
  const orgSlugOf = useOrgSlugOf();
  const { data: clientsData } = useQuery({ ...allClientsQuery(allOrgs ? 'all' : (org?.id ?? '')), enabled: open && (allOrgs || !!org) && canReadClients });
  const clients = clientsData?.items ?? [];
  const [search, setSearch] = useState('');
  // Certificates are searched on the server, 150 ms after the last keystroke;
  // an empty query lists none.
  const [debounced, setDebounced] = useState('');
  useEffect(() => {
    const t = window.setTimeout(() => setDebounced(search.trim()), search.trim() === '' ? 0 : 150);
    return () => window.clearTimeout(t);
  }, [search]);
  const { data: found } = useQuery({
    ...certificateSearchQuery(org?.id ?? '', debounced),
    enabled: open && !!org && (canReadCerts || canIssue) && debounced !== '',
    placeholderData: keepPreviousData,
  });
  const certs = search.trim() === '' ? [] : (found?.items ?? []);
  // Escape and an overlay click close the palette without going through run().
  useEffect(() => {
    if (!open) setSearch('');
  }, [open]);

  const run = (fn: () => void) => {
    onOpenChange(false);
    setSearch('');
    fn();
  };
  const pages: { label: string; keywords: string[]; go: () => void }[] = [
    ...(allOrgs
      ? [
          { label: 'Overview', keywords: ['dashboard', 'triage'], go: () => void navigate({ to: '/o/$org/overview', params: { org: ALL_ORGS_SLUG } }) },
          { label: 'Certificates', keywords: ['list'], go: () => void navigate({ to: '/o/$org/certificates', params: { org: ALL_ORGS_SLUG } }) },
          ...(canReadClients
            ? [{ label: 'Clients', keywords: ['agents', 'hosts', 'fleet'], go: () => void navigate({ to: '/o/$org/clients', params: { org: ALL_ORGS_SLUG } }) }]
            : []),
          ...(canReadAudit
            ? [{ label: 'Audit log', keywords: ['events', 'history', 'who', 'changes'], go: () => void navigate({ to: '/o/$org/audit', params: { org: ALL_ORGS_SLUG } }) }]
            : []),
        ]
      : org
        ? [
            { label: 'Overview', keywords: ['dashboard', 'triage'], go: () => void navigate({ to: '/o/$org/overview', params: { org: org.slug } }) },
            { label: 'Flow', keywords: ['map', 'system', 'path', 'topology'], go: () => void navigate({ to: '/o/$org/flow', params: { org: org.slug } }) },
            ...(canReadCerts
              ? [{ label: 'Certificates', keywords: ['list'], go: () => void navigate({ to: '/o/$org/certificates', params: { org: org.slug } }) }]
              : []),
            ...(canReadClients
              ? [{ label: 'Clients', keywords: ['agents', 'hosts', 'fleet'], go: () => void navigate({ to: '/o/$org/clients', params: { org: org.slug } }) }]
              : []),
            ...(canReadCas
              ? [{ label: 'Issuers: CAs', keywords: ['ca', 'acme', 'directory'], go: () => void navigate({ to: '/o/$org/issuers/cas', params: { org: org.slug } }) }]
              : []),
            ...(canReadCas
              ? [
                  {
                    label: 'Issuers: New private CA',
                    keywords: ['private', 'built-in', 'vault', 'pki', 'root'],
                    go: () =>
                      void navigate({ to: '/o/$org/issuers/cas', params: { org: org.slug }, search: { edit: 'new', kind: 'localca' } }),
                  },
                ]
              : []),
            ...(canReadAccounts
              ? [{ label: 'Issuers: ACME accounts', keywords: ['account'], go: () => void navigate({ to: '/o/$org/issuers/accounts', params: { org: org.slug } }) }]
              : []),
            ...(canReadDnsCreds
              ? [{ label: 'Issuers: DNS credentials', keywords: ['dns', 'provider', 'credential'], go: () => void navigate({ to: '/o/$org/issuers/dns', params: { org: org.slug } }) }]
              : []),
            ...(canReadDelivery
              ? [
                  { label: 'Delivery: Deploy targets', keywords: ['traefik', 'target'], go: () => void navigate({ to: '/o/$org/delivery/targets', params: { org: org.slug } }) },
                  { label: 'Delivery: File layouts', keywords: ['layout', 'files', 'output', 'pem'], go: () => void navigate({ to: '/o/$org/delivery/layouts', params: { org: org.slug } }) },
                  { label: 'Delivery: Hooks', keywords: ['hook', 'reload', 'command'], go: () => void navigate({ to: '/o/$org/delivery/hooks', params: { org: org.slug } }) },
                ]
              : []),
            ...(canReadAlerts
              ? [
                  { label: 'Alerts: Channels', keywords: ['notifications', 'webhook', 'email', 'discord', 'ntfy'], go: () => void navigate({ to: '/o/$org/alerts/channels', params: { org: org.slug } }) },
                  { label: 'Alerts: Monitors', keywords: ['tls', 'monitor', 'scan'], go: () => void navigate({ to: '/o/$org/alerts/monitors', params: { org: org.slug } }) },
                  { label: 'Alerts: Events', keywords: ['events', 'deliveries'], go: () => void navigate({ to: '/o/$org/alerts/events', params: { org: org.slug } }) },
                ]
              : []),
            ...(canReadAudit
              ? [{ label: 'Audit log', keywords: ['events', 'history', 'who', 'changes'], go: () => void navigate({ to: '/o/$org/audit', params: { org: org.slug } }) }]
              : []),
          ]
        : []),
    { label: 'Settings: General', keywords: ['base url'], go: () => void navigate({ to: '/settings/$section', params: { section: 'general' } }) },
    ...(canReadUsers
      ? [{ label: 'Settings: Access', keywords: ['users', 'roles', 'bindings', 'api keys'], go: () => void navigate({ to: '/settings/$section', params: { section: 'access' } }) }]
      : []),
    { label: 'Settings: Authentication', keywords: ['oidc', 'sso', 'single sign-on', 'groups'], go: () => void navigate({ to: '/settings/$section', params: { section: 'authentication' } }) },
    { label: 'Settings: Issuance defaults', keywords: ['defaults', 'renewal', 'key type'], go: () => void navigate({ to: '/settings/$section', params: { section: 'issuance-defaults' } }) },
    { label: 'Settings: Agents', keywords: ['agent ca', 'listener', 'rotation', 'heartbeat'], go: () => void navigate({ to: '/settings/$section', params: { section: 'agents' } }) },
    {
      label: 'Settings: Integrations',
      keywords: ['vault', 'approle', 'openbao', 'integrations', 'smtp', 'email', 'prometheus', 'metrics', 'notifications'],
      go: () => void navigate({ to: '/settings/$section', params: { section: 'integrations' } }),
    },
    { label: 'Settings: Backups', keywords: ['backup', 'restore', 'encryption key', 'kek'], go: () => void navigate({ to: '/settings/$section', params: { section: 'backup' } }) },
    // Task 7 (Phase 6B): runs the same `runBackup` helper as the section's
    // own "Back up now" button; a failure is already toasted by runBackup.
    ...(canSettingsWrite
      ? [
          {
            label: 'Settings: Back up now',
            keywords: ['backup', 'download', 'archive'],
            go: () => {
              void runBackup(qc).catch(() => undefined);
            },
          },
        ]
      : []),
  ];

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Command palette"
      description="Jump to a certificate or page, or run an action"
      className="cf-command-palette"
      // M3: cmdk's default filter also matches against `value` (this palette's
      // internal `cert:<uuid>`/`page:<label>`/`action:*`/`renew:<uuid>` ids),
      // so typing a stray "cert" or part of a uuid could match every row —
      // keywordFilter (as every other picker in the app) matches only against
      // each item's own `keywords`, never its internal value.
      commandProps={{ filter: keywordFilter }}
    >
      <CommandInput placeholder="www.example.com" value={search} onValueChange={setSearch} />
      <CommandList>
        <CommandEmpty>No match.</CommandEmpty>
        {/* Certificates before Actions (review fix): cmdk auto-highlights
            the first matching item in DOM order, so with a matching
            certificate name typed, Enter must navigate to it — not run a
            "Renew <name>" action that happened to render first. */}
        {org && canReadCerts && (
          <CommandGroup heading="Certificates">
            {certs.map((c) => (
              <CommandItem
                key={c.id}
                value={`cert:${c.id}`}
                keywords={[c.name, c.commonName, ...c.sans]}
                onSelect={() => run(() => void navigate({ to: '/o/$org/certificates/$id/$tab', params: { org: org.slug, id: c.id, tab: 'overview' } }))}
              >
                <ShieldCheck className="size-4" aria-hidden />
                <span>{c.name}</span>
                <span className="ml-auto truncate font-mono text-xs text-ink-muted">{c.commonName}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {(org || allOrgs) && canReadClients && clients.length > 0 && (
          <CommandGroup heading="Clients">
            {clients.map((c) => (
              <CommandItem
                key={c.id}
                value={`client:${c.id}`}
                keywords={[c.name, c.hostname]}
                onSelect={() => run(() => void navigate({ to: '/o/$org/clients/$id', params: { org: allOrgs ? orgSlugOf(c.orgId) : org!.slug, id: c.id } }))}
              >
                <Server className="size-4" aria-hidden />
                <span>{c.name}</span>
                <span className="ml-auto truncate font-mono text-xs text-ink-muted">{c.hostname}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {org && (canCreate || canWriteClients || (canIssue && search.trim() !== '')) && (
          <CommandGroup heading="Actions">
            {canCreate && (
              <CommandItem
                value="action:new-certificate"
                keywords={['new', 'issue', 'create', 'certificate']}
                onSelect={() => run(() => void navigate({ to: '/o/$org/certificates/new', params: { org: org.slug } }))}
              >
                <Plus className="size-4" aria-hidden />
                New certificate
              </CommandItem>
            )}
            {canCreate && (
              <CommandItem
                value="action:import-certificates"
                keywords={['import', 'acme.sh', 'certbot', 'migrate']}
                onSelect={() => run(() => void navigate({ to: '/o/$org/certificates/import', params: { org: org.slug } }))}
              >
                <FolderInput className="size-4" aria-hidden />
                Import certificates
              </CommandItem>
            )}
            {canCreate && (
              <CommandItem
                value="action:upload-certificate"
                keywords={['upload', 'pem', 'pkcs12', 'pfx', 'external']}
                onSelect={() => run(() => void navigate({ to: '/o/$org/certificates/upload', params: { org: org.slug } }))}
              >
                <Upload className="size-4" aria-hidden />
                Upload certificate
              </CommandItem>
            )}
            {canWriteClients && (
              <CommandItem
                value="action:enrol-client"
                keywords={['enrol', 'enroll', 'agent', 'client', 'token']}
                onSelect={() => run(() => void navigate({ to: '/o/$org/clients/new', params: { org: org.slug } }))}
              >
                <Plus className="size-4" aria-hidden />
                Enrol client
              </CommandItem>
            )}
            {canIssue &&
              search.trim() !== '' &&
              certs.map((c) => (
                <CommandItem
                  key={`renew:${c.id}`}
                  value={`renew:${c.id}`}
                  keywords={['renew', c.name, c.commonName, ...c.sans]}
                  onSelect={() => run(() => renew.mutate([c.id], renewToastHandlers(c.name)))}
                >
                  <RotateCw className="size-4" aria-hidden />
                  Renew {c.name}
                </CommandItem>
              ))}
          </CommandGroup>
        )}
        <CommandGroup heading="Pages">
          {pages.map((p) => (
            <CommandItem key={p.label} value={`page:${p.label}`} keywords={[p.label, ...p.keywords]} onSelect={() => run(p.go)}>
              <FileText className="size-4" aria-hidden />
              {p.label}
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
