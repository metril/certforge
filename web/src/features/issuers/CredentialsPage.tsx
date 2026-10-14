import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { toast } from 'sonner';
import { FlaskConical, Pencil, Plus, Trash2 } from 'lucide-react';
import { dnsCredentialUsageQuery, dnsCredentialsQuery, metaSchemasQuery, useDeleteCredential } from '@/api/queries/dns';
import { errorMessage } from '@/api/errors';
import { plural } from '@/api/queries/certificates';
import type { DnsCredential, ProviderSchema } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HintLabel } from '@/components/HintLabel';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { UsagePopover } from '@/components/UsagePopover';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ProviderPicker } from '@/forms/ProviderPicker';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { IssuersHeader } from './IssuersLayout';
import { CredentialSheet } from './CredentialSheet';
import { TestCredentialDialog } from './TestCredentialDialog';
import { IconButton } from '@/components/IconButton';

type SheetState = { provider: ProviderSchema; credential?: DnsCredential } | null;

function Header() {
  return (
    <TableHeader>
      <TableRow>
        <TableHead>Name</TableHead>
        <TableHead className="w-28">
          <HintLabel id="dns.usedBy">Used by</HintLabel>
        </TableHead>
        <TableHead className="w-32">
          <span className="sr-only">Actions</span>
        </TableHead>
      </TableRow>
    </TableHeader>
  );
}

export function CredentialsPage() {
  const org = useOrg();
  const me = useMe();
  const qc = useQueryClient();
  const canWrite = can(me, 'dnscreds:write', org.id);
  const { data: creds = [], isPending, isError, error, refetch } = useQuery(dnsCredentialsQuery(org.id));
  const { data: meta, isPending: metaPending } = useQuery(metaSchemasQuery);
  const del = useDeleteCredential(org.id);
  const [picker, setPicker] = useState(false);
  const [sheet, setSheet] = useState<SheetState>(null);
  const [testing, setTesting] = useState<DnsCredential | null>(null);
  const [deleting, setDeleting] = useState<DnsCredential | null>(null);
  const providers = meta?.dnsProviders ?? [];
  const providerOf = (code: string) => providers.find((p) => p.code === code);
  const { edit } = useSearch({ from: '/_app/o/$org/issuers/dns' });
  const navigate = useNavigate({ from: '/o/$org/issuers/dns' });
  // `?edit=<id>` (an entity link) opens that credential's sheet once, then leaves the URL clean;
  // an id that no longer resolves says so instead of doing nothing.
  useEffect(() => {
    if (!edit || isPending || metaPending) return;
    const credential = creds.find((c) => c.id === edit);
    const provider = credential && meta?.dnsProviders.find((p) => p.code === credential.providerCode);
    if (credential && provider) setSheet({ provider, credential });
    else toast.error('Credential not found.');
    void navigate({ search: {}, replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edit, isPending, metaPending]);

  const showList = !isPending && !isError && creds.length > 0;
  return (
    <>
      <IssuersHeader
        help="dns.provider"
        actions={
          showList ? (
            <PermissionTip allowed={canWrite} action="dnscreds:write">
              <Button disabled={!canWrite} onClick={() => setPicker(true)}>
                <Plus className="size-4" aria-hidden />
                Add credential
              </Button>
            </PermissionTip>
          ) : undefined
        }
      />
      <section className="grid gap-4" aria-label="DNS credentials">
        {isPending ? (
          // Fix round 1: a loading table row (not a bare paragraph), so the
          // column layout doesn't jump once data arrives.
          <Table className="table-fixed">
            <Header />
            <TableBody>
              <TableRow>
                <TableCell colSpan={3} className="py-10 text-center text-sm text-ink-muted">
                  Loading…
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        ) : isError ? (
          <ErrorState message={`Couldn't load DNS credentials. ${errorMessage(error)}`} onRetry={() => void refetch()} />
        ) : creds.length === 0 ? (
          <EmptyState message="No DNS credentials yet.">
            <PermissionTip allowed={canWrite} action="dnscreds:write">
              <Button disabled={!canWrite} onClick={() => setPicker(true)}>
                Add credential
              </Button>
            </PermissionTip>
          </EmptyState>
        ) : (
          <>
            <Table className="table-fixed">
              <Header />
              <TableBody>
                {creds.map((c) => {
                  const provider = providerOf(c.providerCode);
                  // preflight A14: usedBy (certificates and defaults) comes
                  // straight from the API; no client-side counting.
                  const usedBy = c.usedBy ?? 0;
                  // Fix round 1: explain the disabled Edit button — the
                  // provider list is still loading, or the credential's own
                  // provider code isn't (or no longer is) in it.
                  const editReason = metaPending ? 'Provider data is loading.' : `Unknown provider "${c.providerCode}".`;
                  return (
                    <TableRow key={c.id}>
                      <TableCell className="py-1.5">
                        <PrimaryCell primary={c.name} meta={[provider?.name ?? c.providerCode]} />
                      </TableCell>
                      <TableCell className="py-1">
                        <UsagePopover
                          label={`Used by ${usedBy}`}
                          count={usedBy}
                          allowed={can(me, 'dnscreds:read', org.id) && can(me, 'certs:read', org.id)}
                          queryKey={['dns-credential', org.id, c.id]}
                          load={async () => {
                            const u = await qc.fetchQuery(dnsCredentialUsageQuery(org.id, c.id));
                            return {
                              items: u.certificates.map((x) => ({ id: x.id, name: x.name, kind: 'certificate' as const })),
                              note: u.defaults > 0 ? `${plural(u.defaults, 'default set')} in Settings` : undefined,
                            };
                          }}
                        />
                      </TableCell>
                      <TableCell className="py-1 text-right whitespace-nowrap">
                        <IconButton tip={canWrite ? undefined : `Needs the dnscreds:write permission`}
                            variant="ghost"
                            size="icon-sm"
                            className="size-7"
                            disabled={!canWrite}
                            label={`Test ${c.name}`}
                            onClick={() => setTesting(c)}
                          >
                            <FlaskConical className="size-3.5" aria-hidden />
                          </IconButton>
                        {!canWrite ? (
                          <IconButton tip={`Needs the dnscreds:write permission`} variant="ghost" size="icon-sm" className="size-7" label={`Edit ${c.name}`} disabled>
                              <Pencil className="size-3.5" aria-hidden />
                            </IconButton>
                        ) : provider ? (
                          <IconButton
                            variant="ghost"
                            size="icon-sm"
                            className="size-7"
                            label={`Edit ${c.name}`}
                            onClick={() => setSheet({ provider, credential: c })}
                          >
                            <Pencil className="size-3.5" aria-hidden />
                          </IconButton>
                        ) : (
                          <IconButton tip={<>{editReason}</>} variant="ghost" size="icon-sm" className="size-7" label={`Edit ${c.name}`} disabled>
                                  <Pencil className="size-3.5" aria-hidden />
                                </IconButton>
                        )}
                        {/* D13: proactively disable rather than rely only on a
                          409 after the operator types the confirmation text —
                          the 409 path (ConfirmDestructive's inline alert)
                          still covers a usedBy that went stale after load. */}
                        {!canWrite ? (
                          <IconButton tip={`Needs the dnscreds:write permission`} variant="ghost" size="icon-sm" className="size-7" label={`Delete ${c.name}`} disabled>
                              <Trash2 className="size-3.5" aria-hidden />
                            </IconButton>
                        ) : usedBy > 0 ? (
                          <IconButton tip={<>Used by {usedBy}; remove those references first.</>} variant="ghost" size="icon-sm" className="size-7" label={`Delete ${c.name}`} disabled>
                                  <Trash2 className="size-3.5" aria-hidden />
                                </IconButton>
                        ) : (
                          <IconButton variant="ghost" size="icon-sm" className="size-7" label={`Delete ${c.name}`} onClick={() => setDeleting(c)}>
                            <Trash2 className="size-3.5" aria-hidden />
                          </IconButton>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </>
        )}
        <ProviderPicker open={picker} onOpenChange={setPicker} providers={providers} onPickProvider={(p) => setSheet({ provider: p })} />
        {sheet && (
          // Mount only once the provider is chosen so the form initializes from it.
          <CredentialSheet
            key={sheet.credential?.id ?? sheet.provider.code}
            orgId={org.id}
            open
            onOpenChange={(o) => !o && setSheet(null)}
            provider={sheet.provider}
            credential={sheet.credential}
            onChangeProvider={() => {
              setSheet(null);
              setPicker(true);
            }}
          />
        )}
        {testing && <TestCredentialDialog orgId={org.id} credential={testing} onOpenChange={(o) => !o && setTesting(null)} />}
        <ConfirmDestructive
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title="Delete credential"
          // Fix round 1: Delete is only reachable here when usedBy is already
          // 0 (the row's own button is disabled otherwise), so this dialog
          // never has a count to report.
          consequence="Certificates and defaults that reference it can no longer renew."
          confirmText={deleting?.name ?? ''}
          actionLabel="Delete credential"
          onConfirm={() => del.mutateAsync(deleting!.id)}
        />
      </section>
    </>
  );
}
