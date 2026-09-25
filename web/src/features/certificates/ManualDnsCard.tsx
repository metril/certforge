import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, Copy, Hourglass, TriangleAlert } from 'lucide-react';
import { manualDnsQuery, useConfirmManualDns } from '@/api/queries/certificates';
import { errorMessage } from '@/api/errors';
import { CopyField } from '@/components/CopyField';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { fmtDateTime } from '@/lib/time';

const fqdn = (n: string) => (n.endsWith('.') ? n : `${n}.`);

type CopyStatus = 'idle' | 'copied' | 'failed';

/** Mirrors CopyField's own clipboard-copy behaviour (try/catch around
 * navigator.clipboard.writeText, a 1.5s status reset) so tests spying on
 * navigator.clipboard still work, but renders the value with `break-all`
 * instead of CopyField's fixed `truncate` — CopyField itself isn't part of
 * this task's file list, and a TXT value (long, random) needs to stay
 * legible at 375px rather than depend on a hover/focus tooltip. */
function useCopyStatus() {
  const [status, setStatus] = useState<CopyStatus>('idle');
  useEffect(() => {
    if (status === 'idle') return;
    const t = window.setTimeout(() => setStatus('idle'), 1500);
    return () => window.clearTimeout(t);
  }, [status]);
  return {
    status,
    copy: async (value: string) => {
      try {
        if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
        await navigator.clipboard.writeText(value);
        setStatus('copied');
      } catch {
        setStatus('failed');
      }
    },
  };
}

function RecordValue({ value, label }: { value: string; label: string }) {
  const { status, copy } = useCopyStatus();
  return (
    <span className="inline-flex min-w-0 items-start gap-1">
      <code className="min-w-0 break-all font-mono text-xs">{value}</code>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="size-7 shrink-0"
        aria-label={`Copy ${label}`}
        onClick={() => void copy(value)}
      >
        {status === 'copied' && <Check className="size-3.5 text-valid" aria-hidden />}
        {status === 'failed' && <TriangleAlert className="size-3.5 text-failed" aria-hidden />}
        {status === 'idle' && <Copy className="size-3.5" aria-hidden />}
      </Button>
      <span aria-live="polite" className="sr-only">
        {status === 'copied' && 'Copied'}
        {status === 'failed' && 'Copy failed'}
      </span>
    </span>
  );
}

export function ManualDnsCard({ orgId, cert }: { orgId: string; cert: { id: string; name: string } }) {
  const { data: records = [] } = useQuery(manualDnsQuery(orgId, cert.id));
  const confirm = useConfirmManualDns(orgId, cert.id);
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const [copied, setCopied] = useState(false);
  if (records.length === 0) return null;
  const zoneLines = records.map((r) => `${fqdn(r.name)} ${r.ttl} IN TXT "${r.value}"`).join('\n');
  // The schema's expiresAt is optional (a record set from a manual-dns wait
  // that hasn't recorded a deadline, or an older attempt shape); show the
  // deadline line only when at least one record actually carries it.
  const expiresAt = records.find((r) => r.expiresAt)?.expiresAt;

  return (
    <section aria-label={`Manual DNS for ${cert.name}`} className="grid gap-3 rounded-md border border-expiring bg-expiring/10 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Hourglass className="size-4 text-expiring" aria-hidden />
        <h2 className="text-base font-semibold">TXT records for {cert.name}</h2>
        <HelpTip id="manual.records" />
      </div>
      {expiresAt && (
        <p className="flex items-center gap-1.5 text-xs text-ink-muted">
          Add these before {fmtDateTime(expiresAt)}
        </p>
      )}
      {isMdUp ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Value</TableHead>
              <TableHead>TTL</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {records.map((r, i) => (
              <TableRow key={`${r.name}-${i}`} className="h-9">
                <TableCell className="max-w-72">
                  <CopyField value={fqdn(r.name)} label={`name ${r.name}`} />
                </TableCell>
                <TableCell className="font-mono text-xs">{r.type}</TableCell>
                <TableCell className="max-w-96">
                  <RecordValue value={r.value} label={`value for ${r.name} #${i + 1}`} />
                </TableCell>
                <TableCell className="tabular-nums">{r.ttl}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <div className="grid gap-2">
          {records.map((r, i) => (
            <div key={`${r.name}-${i}`} className="grid gap-1.5 rounded-md border border-border bg-panel p-3 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-ink-muted">Name</span>
                <CopyField value={fqdn(r.name)} label={`name ${r.name}`} className="justify-end" />
              </div>
              <div className="grid gap-1">
                <span className="text-xs text-ink-muted">Value</span>
                <RecordValue value={r.value} label={`value for ${r.name} #${i + 1}`} />
              </div>
              <div className="text-xs text-ink-muted">
                {r.type} · TTL {r.ttl}
              </div>
            </div>
          ))}
        </div>
      )}
      {confirm.isError && (
        <p role="alert" className="flex items-center gap-1.5 text-sm text-failed">
          <TriangleAlert className="size-4" aria-hidden />
          {errorMessage(confirm.error)}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          onClick={async () => {
            try {
              if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
              await navigator.clipboard.writeText(zoneLines);
              setCopied(true);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? <Check className="size-4 text-valid" aria-hidden /> : <Copy className="size-4" aria-hidden />}
          Copy all as zone lines
        </Button>
        <Button disabled={confirm.isPending} onClick={() => confirm.mutate()}>
          I've added them
        </Button>
      </div>
    </section>
  );
}
