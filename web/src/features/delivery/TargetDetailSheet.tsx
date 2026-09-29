import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { KeyRound, Pencil, Plus, RotateCw, Server, Trash2 } from 'lucide-react';
import { layoutsQuery } from '@/api/queries/delivery';
import { targetGrantsQuery, useDeleteGrant, useRedeployGrant } from '@/api/queries/grants';
import type { DeployTarget, Grant, ProviderSchema } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ServerDeploymentChip } from '@/components/ServerDeploymentChip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { errorMessage } from '@/api/errors';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { ServerGrantForm } from './ServerGrantForm';

type Props = { orgId: string; orgSlug: string; target: DeployTarget; types: ProviderSchema[]; onEdit: () => void; onOpenChange: (open: boolean) => void };

type Mode = { kind: 'list' } | { kind: 'form'; editing?: Grant };

export function TargetDetailSheet({ orgId, orgSlug, target, types, onEdit, onOpenChange }: Props) {
  const me = useMe();
  const canWrite = can(me, 'clients:write', orgId);
  const canExportKeys = can(me, 'keys:export', orgId);
  const canDelivery = can(me, 'delivery:write', orgId);
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const [mode, setMode] = useState<Mode>({ kind: 'list' });
  const [removing, setRemoving] = useState<Grant | null>(null);
  const q = useQuery(targetGrantsQuery(orgId, target.id));
  const layoutsQ = useQuery(layoutsQuery(orgId));
  const layouts = layoutsQ.data ?? [];
  const redeploy = useRedeployGrant(orgId);
  const del = useDeleteGrant(orgId);

  const typeName = types.find((t) => t.code === target.type)?.name ?? target.type;
  const includeKey = !!(target.config as { includeKey?: boolean }).includeKey;
  const newGrantAllowed = canWrite && (!includeKey || canExportKeys);
  const newGrantReason = !canWrite ? 'clients:write' : 'keys:export';
  const layoutName = (id: string | null) => (id ? (layouts.find((l) => l.id === id)?.name ?? '…') : 'Target files');
  const redeploying = (g: Grant) => redeploy.isPending && redeploy.variables === g.id;

  const openForm = (editing?: Grant) => setMode({ kind: 'form', editing });
  const backToList = () => setMode({ kind: 'list' });

  const newGrantButton = (
    <PermissionTip allowed={newGrantAllowed} action={newGrantReason}>
      <Button type="button" size="sm" disabled={!newGrantAllowed} onClick={() => openForm()}>
        <Plus className="size-4" aria-hidden />
        New server grant
      </Button>
    </PermissionTip>
  );

  const certLink = (g: Grant) => (
    <Link to="/o/$org/certificates/$id/$tab" params={{ org: orgSlug, id: g.certificateId, tab: 'overview' }} className="truncate font-semibold hover:underline">
      {g.certificateName}
    </Link>
  );

  const actions = (g: Grant) => (
    <span className="inline-flex">
      <PermissionTip allowed={canWrite} action="clients:write" side="left">
        <Button
          variant="ghost"
          size="icon-sm"
          className="size-7"
          disabled={!canWrite || redeploying(g)}
          aria-label={`Redeploy ${g.certificateName}`}
          onClick={() => redeploy.mutate(g.id)}
        >
          <RotateCw className="size-3.5" aria-hidden />
        </Button>
      </PermissionTip>
      {/* Batch 4 review: updateServerGrant's own requireKeyIfNeeded gate
          means an includeKey target's grants need keys:export to edit at
          all, not just clients:write — same reasoning as newGrantAllowed
          above, reused here rather than only checking clients:write. */}
      <PermissionTip allowed={newGrantAllowed} action={newGrantReason} side="left">
        <Button
          variant="ghost"
          size="icon-sm"
          className="size-7"
          disabled={!newGrantAllowed}
          aria-label={`Edit layout for ${g.certificateName}`}
          onClick={() => openForm(g)}
        >
          <Pencil className="size-3.5" aria-hidden />
        </Button>
      </PermissionTip>
      <PermissionTip allowed={canWrite} action="clients:write" side="left">
        <Button variant="ghost" size="icon-sm" className="size-7" disabled={!canWrite} aria-label={`Remove ${g.certificateName}`} onClick={() => setRemoving(g)}>
          <Trash2 className="size-3.5" aria-hidden />
        </Button>
      </PermissionTip>
    </span>
  );

  const statusCell = (g: Grant) => (
    <span className="inline-flex items-center gap-1.5">
      <ServerDeploymentChip status={g.serverDeployment!.status} lastError={g.serverDeployment!.lastError} withHelp />
      {g.serverDeployment!.deployedAt && <span className="text-xs text-ink-muted">{relTime(g.serverDeployment!.deployedAt)}</span>}
    </span>
  );

  const grantsList = () => {
    if (q.isError) return <ErrorState message={`Couldn't load grants. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
    if (q.isPending) return <p className="py-6 text-center text-sm text-ink-muted">Loading…</p>;
    const grants = q.data;
    if (grants.length === 0) return <EmptyState message="No certificates granted yet.">{newGrantButton}</EmptyState>;
    if (!isMdUp) {
      return (
        <ul aria-label="Grants" className="grid gap-2">
          {grants.map((g) => (
            <li key={g.id} className="grid gap-2 rounded-md border border-border bg-panel p-3">
              <div className="flex items-center justify-between gap-2">
                {certLink(g)}
                {statusCell(g)}
              </div>
              <span className="truncate text-xs text-ink-muted">{layoutName(g.layoutId)}</span>
              <div className="flex justify-end">{actions(g)}</div>
            </li>
          ))}
        </ul>
      );
    }
    return (
      <Table aria-label="Grants" className="table-fixed">
        <TableHeader>
          <TableRow>
            <TableHead className="w-44">Certificate</TableHead>
            <TableHead>Layout</TableHead>
            <TableHead className="w-40">Status</TableHead>
            <TableHead className="w-28">
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {grants.map((g) => (
            <TableRow key={g.id} className="h-9">
              <TableCell className="py-1">{certLink(g)}</TableCell>
              <TableCell className="truncate py-1">{layoutName(g.layoutId)}</TableCell>
              <TableCell className="py-1">{statusCell(g)}</TableCell>
              <TableCell className="py-1 text-right">{actions(g)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-2xl">
        <SheetHeader>
          <div className="flex items-start justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <SheetTitle>{target.name}</SheetTitle>
              <span className="text-xs text-ink-muted">{typeName}</span>
              <ToneChip tone="neutral" icon={Server} label="Runs on server" />
              {includeKey && <ToneChip tone="neutral" icon={KeyRound} label="Includes key" />}
            </div>
            <PermissionTip allowed={canDelivery} action="delivery:write">
              <Button type="button" variant="outline" size="sm" disabled={!canDelivery} onClick={onEdit}>
                <Pencil className="size-3.5" aria-hidden />
                Edit
              </Button>
            </PermissionTip>
          </div>
          <SheetDescription className="sr-only">{typeName} deploy target</SheetDescription>
        </SheetHeader>
        <div className="grid gap-4 px-4">
          {mode.kind === 'form' ? (
            <ServerGrantForm orgId={orgId} targetId={target.id} editing={mode.editing} onBack={backToList} onDone={backToList} />
          ) : (
            <>
              <div className="flex items-center justify-between gap-2">
                <h3 className="flex items-center gap-1.5 text-sm font-semibold">
                  Grants <HelpTip id="grant.server" />
                </h3>
                {(q.data?.length ?? 0) > 0 && newGrantButton}
              </div>
              {grantsList()}
            </>
          )}
        </div>
      </SheetContent>
      <ConfirmDestructive
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title="Remove grant?"
        consequence="CertForge stops writing this certificate to the target; data already in Vault stays."
        confirmText={removing?.certificateName ?? ''}
        actionLabel="Remove"
        onConfirm={() => del.mutateAsync({ id: removing!.id })}
      />
    </Sheet>
  );
}
