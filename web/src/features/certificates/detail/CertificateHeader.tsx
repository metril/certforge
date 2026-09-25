import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { CircleAlert, CopyPlus, Download, MoreHorizontal, RotateCw, Trash2 } from 'lucide-react';
import { accountsQuery } from '@/api/queries/accounts';
import { casQuery } from '@/api/queries/cas';
import { certificateQuery, useDeleteCertificates, useRenewCertificates } from '@/api/queries/certificates';
import type { Certificate, EffectiveMap } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { StatusChip } from '@/components/StatusChip';
import { CertValidity } from '@/components/ValidityBar';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { renewToastHandlers } from '@/lib/renewToast';
import { relDays } from '@/lib/time';

type Props = { cert: Certificate; orgId: string; orgSlug: string; onDownload: () => void; onRenewed: () => void };

// Header actions (controller ruling): Renew now, Download, and Duplicate
// (into the wizard's `new` route, pre-filled) sit inline; Delete is the only
// destructive action and lives in the overflow menu. Revoke is not in Phase
// 1's API and is not offered anywhere here.
export function CertificateHeader({ cert, orgId, orgSlug, onDownload, onRenewed }: Props) {
  const renew = useRenewCertificates(orgId);
  const del = useDeleteCertificates(orgId);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState(false);
  const { data: cas = [] } = useQuery(casQuery(orgId));
  const { data: accounts = [] } = useQuery(accountsQuery(orgId));
  const eff = cert.effective as EffectiveMap | undefined;
  const caName = cas.find((c) => c.id === eff?.caId?.value)?.name;
  const account = accounts.find((a) => a.id === eff?.accountId?.value)?.email;

  return (
    <header className="grid gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold">{cert.name}</h1>
            <StatusChip status={cert.status} withHelp />
          </div>
          <span className="truncate font-mono text-xs text-ink-muted">{cert.commonName}</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            disabled={renew.isPending}
            onClick={() => {
              const toasts = renewToastHandlers(cert.name);
              renew.mutate([cert.id], {
                ...toasts,
                onSuccess: () => {
                  toasts.onSuccess();
                  onRenewed();
                },
              });
            }}
          >
            <RotateCw className="size-4" aria-hidden />
            Renew now
          </Button>
          <Button variant="outline" disabled={!cert.currentVersion} onClick={onDownload}>
            <Download className="size-4" aria-hidden />
            Download
          </Button>
          <Button variant="ghost" asChild>
            <Link to="/o/$org/certificates/new" params={{ org: orgSlug }} search={{ from: cert.id }}>
              <CopyPlus className="size-4" aria-hidden />
              Duplicate
            </Link>
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label="More actions">
                <MoreHorizontal className="size-4" aria-hidden />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem variant="destructive" onSelect={() => setConfirm(true)}>
                <Trash2 className="size-4" aria-hidden />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      {cert.currentVersion ? <CertValidity cert={cert} size="full" /> : <p className="text-sm text-ink-muted">Not issued yet</p>}
      <dl className="flex flex-wrap gap-x-8 gap-y-1 text-sm">
        <div className="flex gap-2">
          <dt className="text-ink-muted">CA</dt>
          <dd>{caName ?? '–'}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-ink-muted">Account</dt>
          <dd className="font-mono text-xs leading-5">{account ?? '–'}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-ink-muted">Next renewal</dt>
          <dd>{cert.nextRenewAt ? relDays(cert.nextRenewAt) : '–'}</dd>
        </div>
        {cert.failureCount > 0 && (
          <div className="flex min-w-0 gap-2">
            <dt className="text-ink-muted">Failures</dt>
            <dd className="flex min-w-0 items-center gap-1">
              <CircleAlert className="size-4 shrink-0 text-failed" aria-hidden />
              {cert.failureCount}
              {cert.lastError && (
                <span className="max-w-96 truncate text-ink-muted" title={cert.lastError}>
                  {cert.lastError}
                </span>
              )}
            </dd>
          </div>
        )}
      </dl>
      <ConfirmDestructive
        open={confirm}
        onOpenChange={setConfirm}
        title="Delete certificate"
        consequence="Its versions and private keys are deleted and it stops renewing."
        confirmText={cert.name}
        actionLabel="Delete certificate"
        onConfirm={async () => {
          await del.mutateAsync([cert.id]);
          // Fix round 1 (review, Important #5): useDeleteCertificates's own
          // onSuccess invalidates the whole `['certs', orgId]` family,
          // including this certificate's own query — since this page is
          // still mounted and that query is still active, invalidation
          // would otherwise refetch it immediately and briefly flash a 404
          // before the navigate below unmounts the page. cancelQueries stops
          // that in-flight refetch's result from ever being committed;
          // removeQueries drops the now-stale cached data too.
          const key = certificateQuery(orgId, cert.id).queryKey;
          await qc.cancelQueries({ queryKey: key });
          qc.removeQueries({ queryKey: key });
          await navigate({ to: '/o/$org/certificates', params: { org: orgSlug } });
        }}
      />
    </header>
  );
}
