import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { FileText, Plus, RotateCw, ShieldCheck } from 'lucide-react';
import { allCertificatesQuery, useRenewCertificates } from '@/api/queries/certificates';
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { useMe } from '@/lib/org';
import { renewToastHandlers } from '@/lib/renewToast';
import { keywordFilter } from '@/lib/utils';

/**
 * Ctrl/Cmd-K palette: jump to a certificate by name, common name, or any
 * SAN, jump to a page, or run "New certificate"/"Renew <name>". Every
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
  // No org (a fresh account with none yet, or /settings/*): certificate
  // search and the org-scoped pages below are left out, matching Sidebar's
  // own "disabled without an org" treatment (lib/nav.ts's NO_ORG).
  const org = me.orgs.find((o) => o.slug === params.org) ?? me.orgs[0];
  const navigate = useNavigate();
  const renew = useRenewCertificates(org?.id ?? '');
  const { data: certs = [] } = useQuery({ ...allCertificatesQuery(org?.id ?? ''), enabled: open && !!org });
  const [search, setSearch] = useState('');

  const run = (fn: () => void) => {
    onOpenChange(false);
    setSearch('');
    fn();
  };
  const pages: { label: string; keywords: string[]; go: () => void }[] = [
    ...(org
      ? [
          { label: 'Overview', keywords: ['dashboard', 'triage'], go: () => void navigate({ to: '/o/$org/overview', params: { org: org.slug } }) },
          { label: 'Certificates', keywords: ['list'], go: () => void navigate({ to: '/o/$org/certificates', params: { org: org.slug } }) },
          { label: 'Issuers: CAs', keywords: ['ca', 'acme', 'directory'], go: () => void navigate({ to: '/o/$org/issuers/cas', params: { org: org.slug } }) },
          { label: 'Issuers: ACME accounts', keywords: ['account'], go: () => void navigate({ to: '/o/$org/issuers/accounts', params: { org: org.slug } }) },
          { label: 'Issuers: DNS credentials', keywords: ['dns', 'provider', 'credential'], go: () => void navigate({ to: '/o/$org/issuers/dns', params: { org: org.slug } }) },
        ]
      : []),
    { label: 'Settings: General', keywords: ['base url'], go: () => void navigate({ to: '/settings/$section', params: { section: 'general' } }) },
    { label: 'Settings: Access', keywords: ['users', 'roles', 'bindings', 'api keys'], go: () => void navigate({ to: '/settings/$section', params: { section: 'access' } }) },
    { label: 'Settings: Authentication', keywords: ['oidc', 'sso', 'single sign-on', 'groups'], go: () => void navigate({ to: '/settings/$section', params: { section: 'authentication' } }) },
    { label: 'Settings: Issuance defaults', keywords: ['defaults', 'renewal', 'key type'], go: () => void navigate({ to: '/settings/$section', params: { section: 'issuance-defaults' } }) },
    { label: 'Settings: Backup and keys', keywords: ['kek', 'backup'], go: () => void navigate({ to: '/settings/$section', params: { section: 'backup' } }) },
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
        {org && (
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
        {org && (
          <CommandGroup heading="Actions">
            <CommandItem
              value="action:new-certificate"
              keywords={['new', 'issue', 'create', 'certificate']}
              onSelect={() => run(() => void navigate({ to: '/o/$org/certificates/new', params: { org: org.slug } }))}
            >
              <Plus className="size-4" aria-hidden />
              New certificate
            </CommandItem>
            {search.trim() !== '' &&
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
