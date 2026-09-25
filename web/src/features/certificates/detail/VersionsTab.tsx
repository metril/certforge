import { useQuery } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { versionsQuery } from '@/api/queries/certificates';
import type { Certificate } from '@/api/types';
import { CopyField } from '@/components/CopyField';
import { EmptyState } from '@/components/EmptyState';
import { HelpTip } from '@/components/HelpTip';
import { ValidityBar } from '@/components/ValidityBar';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { validityTone } from '@/lib/status';
import { fmtDate } from '@/lib/time';

export function VersionsTab({ cert, orgId, onDownload }: { cert: Certificate; orgId: string; onDownload: (versionId: string) => void }) {
  const { data = [], isPending } = useQuery(versionsQuery(orgId, cert.id));
  const versions = [...data].sort((a, b) => Date.parse(b.notBefore) - Date.parse(a.notBefore));
  if (!isPending && versions.length === 0) return <EmptyState message="No versions yet." />;
  return (
    <Table aria-label="Versions" className="mt-4">
      <TableHeader>
        <TableRow>
          <TableHead>Serial</TableHead>
          <TableHead>
            <span className="inline-flex items-center gap-1">
              Validity <HelpTip id="cert.versions" />
            </span>
          </TableHead>
          <TableHead>SHA-256</TableHead>
          <TableHead>Source</TableHead>
          <TableHead className="w-12">
            <span className="sr-only">Download</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {versions.map((v, i) => {
          const current = v.id === cert.currentVersion?.id;
          const successor = i > 0 ? versions[i - 1]! : null;
          return (
            <TableRow key={v.id} className="h-9">
              <TableCell>
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
              <TableCell className="capitalize">{v.source}</TableCell>
              <TableCell>
                <Button variant="ghost" size="icon" aria-label={`Download version ${v.serial}`} onClick={() => onDownload(v.id)}>
                  <Download className="size-4" aria-hidden />
                </Button>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
