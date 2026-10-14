import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Eye, Pencil, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { plural } from '@/api/queries/certificates';
import { CREDENTIAL_KIND_LABEL, deployCredentialsQuery, useDeleteDeployCredential } from '@/api/queries/deployCredentials';
import { credentialTargetsQuery } from '@/api/queries/delivery';
import { metaSchemasQuery } from '@/api/queries/dns';
import type { DeployCredential } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HintLabel } from '@/components/HintLabel';
import { IconButton } from '@/components/IconButton';
import { PermissionTip } from '@/components/PermissionTip';
import { PrimaryCell } from '@/components/PrimaryCell';
import { Button } from '@/components/ui/button';
import { UsagePopover } from '@/components/UsagePopover';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { failedWithoutData } from '@/lib/queryState';
import { CredentialSheet } from './CredentialSheet';

export function CredentialsPage() {
  const org = useOrg();
  const me = useMe();
  const qc = useQueryClient();
  const canWrite = can(me, 'deploycreds:write', org.id);
  const { edit } = useSearch({ from: '/_app/o/$org/delivery/credentials' });
  const navigate = useNavigate({ from: '/o/$org/delivery/credentials' });
  const q = useQuery(deployCredentialsQuery(org.id));
  const metaQ = useQuery(metaSchemasQuery);
  const del = useDeleteDeployCredential(org.id);
  const [deleting, setDeleting] = useState<DeployCredential | null>(null);
  const openSheet = (id: string | undefined) => void navigate({ search: { edit: id }, replace: id === undefined });
  const creds = q.data ?? [];
  const kinds = metaQ.data?.deployCredentials ?? [];
  // A stale `?edit=<id>` (deleted elsewhere) is dropped once the list has loaded.
  useEffect(() => {
    if (q.isPending || !edit || edit === 'new') return;
    if (!creds.some((c) => c.id === edit)) {
      openSheet(undefined);
      toast.error('Credential not found.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edit, q.isPending, creds.map((c) => c.id).join(',')]);
  const editing = creds.find((c) => c.id === edit);
  const add = (
    <PermissionTip allowed={canWrite} action="deploycreds:write">
      <Button disabled={!canWrite || kinds.length === 0} onClick={() => openSheet('new')}>
        <Plus className="size-4" aria-hidden />
        Add credential
      </Button>
    </PermissionTip>
  );
  const metaLine = (c: DeployCredential) => {
    const user = typeof c.config?.username === 'string' ? c.config.username : '';
    return [CREDENTIAL_KIND_LABEL[c.kind] ?? c.kind, user];
  };

  return (
    <div className="grid gap-4">
      {q.isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : failedWithoutData(q) ? (
        <ErrorState message={`Couldn't load credentials. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : creds.length === 0 ? (
        <EmptyState message="No saved credentials yet.">{add}</EmptyState>
      ) : (
        <>
          <div className="flex justify-end">{add}</div>
          <Table aria-label="Deploy credentials" className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead className="w-28">
                  <HintLabel id="deployCred.usedBy">Used by</HintLabel>
                </TableHead>
                <TableHead className="w-20">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {creds.map((c) => {
                const usedBy = c.usedBy ?? 0;
                const delTip = !canWrite ? 'Needs the deploycreds:write permission' : usedBy > 0 ? `Used by ${plural(usedBy, 'target')}. Detach them first.` : undefined;
                return (
                  <TableRow key={c.id}>
                    <TableCell className="py-1.5">
                      <PrimaryCell primary={c.name} meta={metaLine(c)} />
                    </TableCell>
                    <TableCell className="py-1">
                      {usedBy > 0 ? (
                        <UsagePopover
                          label={plural(usedBy, 'target')}
                          count={usedBy}
                          allowed={can(me, 'delivery:read', org.id)}
                          queryKey={['deploy-credential', org.id, c.id]}
                          load={async () => ({ items: (await qc.fetchQuery(credentialTargetsQuery(org.id, c.id))).map((t) => ({ id: t.id, name: t.name, kind: 'target' as const })) })}
                        />
                      ) : (
                        <span className="text-ink-muted">–</span>
                      )}
                    </TableCell>
                    <TableCell className="py-1 text-right whitespace-nowrap">
                      <IconButton variant="ghost" size="icon-sm" className="size-7" label={canWrite ? `Edit ${c.name}` : `View ${c.name}`} onClick={() => openSheet(c.id)}>
                        {canWrite ? <Pencil className="size-3.5" aria-hidden /> : <Eye className="size-3.5" aria-hidden />}
                      </IconButton>
                      <IconButton
                        tip={delTip}
                        variant="ghost"
                        size="icon-sm"
                        className="size-7"
                        disabled={!canWrite || usedBy > 0}
                        label={`Delete ${c.name}`}
                        onClick={() => setDeleting(c)}
                      >
                        <Trash2 className="size-3.5" aria-hidden />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </>
      )}
      {((canWrite && edit === 'new') || editing) && kinds.length > 0 && (
        <CredentialSheet key={edit} orgId={org.id} credential={editing} kinds={kinds} readOnly={!canWrite} onOpenChange={(o) => !o && openSheet(undefined)} />
      )}
      <ConfirmDestructive
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete credential"
        consequence="Its secrets are gone for good. Targets can no longer pick it."
        confirmText={deleting?.name ?? ''}
        actionLabel="Delete credential"
        onConfirm={() => del.mutateAsync(deleting!.id)}
      />
    </div>
  );
}
