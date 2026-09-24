import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FlaskConical, Pencil, Plus, Trash2 } from 'lucide-react';
import { dnsCredentialsQuery, metaSchemasQuery, useDeleteCredential } from '@/api/queries/dns';
import { errorMessage } from '@/api/errors';
import type { DnsCredential, ProviderSchema } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { ProviderPicker } from '@/forms/ProviderPicker';
import { useOrg } from '@/lib/org';
import { cn } from '@/lib/utils';
import { CredentialSheet } from './CredentialSheet';
import { TestCredentialDialog } from './TestCredentialDialog';

// Fix round 1 (#3/#4) elsewhere: first column stays put while the row
// scrolls horizontally; matches the row's own bg so scrolled-under cells
// don't show through. Same convention as CasPage/AccountsPage.
const stickyCol = 'sticky left-0 z-10 bg-panel';

type SheetState = { provider: ProviderSchema; credential?: DnsCredential } | null;

export function CredentialsPage() {
  const org = useOrg();
  const { data: creds = [], isPending, isError, error, refetch } = useQuery(dnsCredentialsQuery(org.id));
  const { data: meta } = useQuery(metaSchemasQuery);
  const del = useDeleteCredential(org.id);
  const [picker, setPicker] = useState(false);
  const [sheet, setSheet] = useState<SheetState>(null);
  const [testing, setTesting] = useState<DnsCredential | null>(null);
  const [deleting, setDeleting] = useState<DnsCredential | null>(null);
  const providers = meta?.dnsProviders ?? [];
  const providerOf = (code: string) => providers.find((p) => p.code === code);

  return (
    <section className="grid gap-4" aria-label="DNS credentials">
      {isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : isError ? (
        <ErrorState message={`Couldn't load DNS credentials. ${errorMessage(error)}`} onRetry={() => void refetch()} />
      ) : creds.length === 0 ? (
        <EmptyState message="No DNS credentials yet.">
          <Button onClick={() => setPicker(true)}>Add credential</Button>
        </EmptyState>
      ) : (
        <>
          <div className="flex justify-end">
            <Button onClick={() => setPicker(true)}>
              <Plus className="size-4" aria-hidden />
              Add credential
            </Button>
          </div>
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={cn('w-40', stickyCol)}>Name</TableHead>
                <TableHead className="w-40">
                  <span className="inline-flex items-center gap-1">
                    Provider <HelpTip id="dns.provider" />
                  </span>
                </TableHead>
                <TableHead className="w-28">
                  <span className="inline-flex items-center gap-1">
                    Used by <HelpTip id="dns.usedBy" />
                  </span>
                </TableHead>
                <TableHead className="w-32">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {creds.map((c) => {
                const provider = providerOf(c.providerCode);
                // preflight A14: usedBy (certificates and defaults) comes
                // straight from the API; no client-side counting.
                const usedBy = c.usedBy ?? 0;
                return (
                  <TableRow key={c.id}>
                    <TableCell className={cn('truncate py-1 font-semibold', stickyCol)}>{c.name}</TableCell>
                    <TableCell className="truncate py-1">{provider?.name ?? <span className="font-mono text-xs">{c.providerCode}</span>}</TableCell>
                    <TableCell className="py-1">{`Used by ${usedBy}`}</TableCell>
                    <TableCell className="py-1 text-right whitespace-nowrap">
                      <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Test ${c.name}`} onClick={() => setTesting(c)}>
                        <FlaskConical className="size-3.5" aria-hidden />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        className="size-7"
                        aria-label={`Edit ${c.name}`}
                        disabled={!provider}
                        onClick={() => provider && setSheet({ provider, credential: c })}
                      >
                        <Pencil className="size-3.5" aria-hidden />
                      </Button>
                      {/* D13: proactively disable rather than rely only on a
                          409 after the operator types the confirmation text —
                          the 409 path (ConfirmDestructive's inline alert)
                          still covers a usedBy that went stale after load. */}
                      {usedBy > 0 ? (
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
        consequence={`Used by ${deleting?.usedBy ?? 0}. Certificates and defaults that reference it can no longer renew.`}
        confirmText={deleting?.name ?? ''}
        actionLabel="Delete credential"
        onConfirm={() => del.mutateAsync(deleting!.id)}
      />
    </section>
  );
}
