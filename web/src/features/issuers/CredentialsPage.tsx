import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FlaskConical, Pencil, Plus, Trash2 } from 'lucide-react';
import { dnsCredentialsQuery, metaSchemasQuery, useDeleteCredential } from '@/api/queries/dns';
import { errorMessage } from '@/api/errors';
import type { DnsCredential, ProviderSchema } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HintLabel } from '@/components/HintLabel';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { ProviderPicker } from '@/forms/ProviderPicker';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { IssuersHeader } from './IssuersLayout';
import { CredentialSheet } from './CredentialSheet';
import { TestCredentialDialog } from './TestCredentialDialog';

// Fix round 1 (#3/#4) elsewhere: first column stays put while the row
// scrolls horizontally; matches the row's own bg so scrolled-under cells
// don't show through. Same convention as CasPage/AccountsPage.
const stickyCol = 'sticky left-0 z-10 bg-panel';

type SheetState = { provider: ProviderSchema; credential?: DnsCredential } | null;

function Header() {
  return (
    <TableHeader>
      <TableRow>
        <TableHead className={stickyCol}>Name</TableHead>
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
                      <TableCell className={cn('py-1.5', stickyCol)}>
                        <PrimaryCell primary={c.name} meta={[provider?.name ?? c.providerCode]} />
                      </TableCell>
                      <TableCell className="py-1">{`Used by ${usedBy}`}</TableCell>
                      <TableCell className="py-1 text-right whitespace-nowrap">
                        <PermissionTip allowed={canWrite} action="dnscreds:write" side="left">
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            className="size-7"
                            disabled={!canWrite}
                            aria-label={`Test ${c.name}`}
                            onClick={() => setTesting(c)}
                          >
                            <FlaskConical className="size-3.5" aria-hidden />
                          </Button>
                        </PermissionTip>
                        {!canWrite ? (
                          <PermissionTip allowed={false} action="dnscreds:write" side="left">
                            <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Edit ${c.name}`} disabled>
                              <Pencil className="size-3.5" aria-hidden />
                            </Button>
                          </PermissionTip>
                        ) : provider ? (
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            className="size-7"
                            aria-label={`Edit ${c.name}`}
                            onClick={() => setSheet({ provider, credential: c })}
                          >
                            <Pencil className="size-3.5" aria-hidden />
                          </Button>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span tabIndex={0} className="inline-flex">
                                <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Edit ${c.name}`} disabled>
                                  <Pencil className="size-3.5" aria-hidden />
                                </Button>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>{editReason}</TooltipContent>
                          </Tooltip>
                        )}
                        {/* D13: proactively disable rather than rely only on a
                          409 after the operator types the confirmation text —
                          the 409 path (ConfirmDestructive's inline alert)
                          still covers a usedBy that went stale after load. */}
                        {!canWrite ? (
                          <PermissionTip allowed={false} action="dnscreds:write" side="left">
                            <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Delete ${c.name}`} disabled>
                              <Trash2 className="size-3.5" aria-hidden />
                            </Button>
                          </PermissionTip>
                        ) : usedBy > 0 ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span tabIndex={0} className="inline-flex">
                                <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Delete ${c.name}`} disabled>
                                  <Trash2 className="size-3.5" aria-hidden />
                                </Button>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>Used by {usedBy}; remove those references first.</TooltipContent>
                          </Tooltip>
                        ) : (
                          <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Delete ${c.name}`} onClick={() => setDeleting(c)}>
                            <Trash2 className="size-3.5" aria-hidden />
                          </Button>
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
          // Mount only once the provider is chosen so the form initialises from it.
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
