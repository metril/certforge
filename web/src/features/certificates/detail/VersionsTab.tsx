import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Ban, Download, KeyRound } from 'lucide-react';
import { casQuery } from '@/api/queries/cas';
import { versionsQuery } from '@/api/queries/certificates';
import type { Certificate, CertificateVersion } from '@/api/types';
import { CopyField } from '@/components/CopyField';
import { EmptyState } from '@/components/EmptyState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { ValidityBar } from '@/components/ValidityBar';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { isPrivate } from '@/lib/caKinds';
import { validityTone } from '@/lib/status';
import { fmtDate, relTime } from '@/lib/time';
import { RevokeVersionDialog } from './RevokeVersionDialog';

// Serial is pinned (`sticky left-0`, like DataTable's own Name column) so it
// stays visible while the rest of the row scrolls horizontally at 375px —
// controller ruling: keep the scrolling table here, no card-row layout.
const STICKY_SERIAL = 'sticky left-0 z-10 bg-panel';

export function VersionsTab({
  cert,
  orgId,
  onDownload,
  onRenew,
  canRevoke,
}: {
  cert: Certificate;
  orgId: string;
  onDownload: (versionId: string) => void;
  onRenew: () => void;
  canRevoke: boolean;
}) {
  const { data = [], isPending } = useQuery(versionsQuery(orgId, cert.id));
  // Task 5: which versions can offer Revoke depends on the certificate's
  // effective CA being private (localca/vaultpki) — the same cas list and
  // lookup CertificateHeader already uses for its CA name.
  const { data: cas = [] } = useQuery(casQuery(orgId));
  const effCa = cas.find((c) => c.id === cert.effective?.caId?.value);
  const privateCa = !!effCa && isPrivate(effCa);
  const [revoking, setRevoking] = useState<CertificateVersion | null>(null);
  const versions = [...data].sort((a, b) => Date.parse(b.notBefore) - Date.parse(a.notBefore));
  if (!isPending && versions.length === 0) {
    return (
      <EmptyState message="No versions yet.">
        <Button onClick={onRenew}>Renew now</Button>
      </EmptyState>
    );
  }
  return (
    <>
      <Table aria-label="Versions" className="mt-4">
        <TableHeader>
          <TableRow>
            <TableHead className={STICKY_SERIAL}>Serial</TableHead>
            <TableHead>
              <span className="inline-flex items-center gap-1">
                Validity <HelpTip id="cert.versions" />
              </span>
            </TableHead>
            <TableHead>SHA-256</TableHead>
            <TableHead>Source</TableHead>
            <TableHead className="w-28">
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {versions.map((v, i) => {
            const current = v.id === cert.currentVersion?.id;
            const successor = i > 0 ? versions[i - 1]! : null;
            return (
              <TableRow key={v.id} className="h-9">
                <TableCell className={STICKY_SERIAL}>
                  <span className="inline-flex items-center gap-2">
                    <CopyField value={v.serial} label="serial" />
                    {current && <span className="rounded-sm bg-primary/10 px-1.5 text-xs font-semibold">Current</span>}
                  </span>
                </TableCell>
                <TableCell className="w-72">
                  <div className="grid gap-0.5">
                    <ValidityBar
                      notBefore={v.notBefore}
                      notAfter={v.notAfter}
                      renewAt={current ? cert.nextRenewAt : null}
                      ghost={successor ? { notBefore: successor.notBefore, notAfter: successor.notAfter } : null}
                      tone={current ? validityTone(cert) : 'neutral'}
                    />
                    <span className="text-xs text-ink-muted">
                      {fmtDate(v.notBefore)} to {fmtDate(v.notAfter)}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="max-w-56">
                  <CopyField value={v.sha256Fingerprint} display={`${v.sha256Fingerprint.slice(0, 16)}…`} label="SHA-256 fingerprint" />
                </TableCell>
                <TableCell className="capitalize">
                  <span className="inline-flex items-center gap-1.5">
                    {v.source}
                    {!v.hasKey && <ToneChip tone="neutral" icon={KeyRound} label="No key" help="download.noKey" />}
                  </span>
                </TableCell>
                <TableCell>
                  <span className="inline-flex items-center gap-1">
                    <Button variant="ghost" size="icon" aria-label={`Download version ${v.serial}`} onClick={() => onDownload(v.id)}>
                      <Download className="size-4" aria-hidden />
                    </Button>
                    {privateCa &&
                      v.source === 'issued' &&
                      (v.revokedAt ? (
                        <ToneChip tone="failed" icon={Ban} label="Revoked" title={relTime(v.revokedAt)} />
                      ) : (
                        <>
                          <PermissionTip allowed={canRevoke} action="certs:issue">
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`Revoke version ${v.serial}`}
                              disabled={!canRevoke}
                              onClick={() => setRevoking(v)}
                            >
                              <Ban className="size-4" aria-hidden />
                            </Button>
                          </PermissionTip>
                          <HelpTip id="version.revoke" />
                        </>
                      ))}
                  </span>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      {revoking && (
        <RevokeVersionDialog open onOpenChange={(o) => !o && setRevoking(null)} orgId={orgId} certId={cert.id} version={revoking} />
      )}
    </>
  );
}
