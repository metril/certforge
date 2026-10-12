import { useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ToggleGroup } from 'radix-ui';
import { Check, CircleAlert, Globe, LoaderCircle, ShieldAlert, ShieldCheck, TriangleAlert, Upload } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { casQuery } from '@/api/queries/cas';
import { usePeekTls } from '@/api/queries/tls';
import type { TlsPeekCertificate } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { help } from '@/lib/help';
import { appendPem, cnOfDn, fileBytesToPem, summarizeBundle } from '@/lib/pem';
import { fmtDate } from '@/lib/time';
import { cn } from '@/lib/utils';

/** Where Fetch and From saved CA act: the org, and whether the caller holds
 * delivery:write or cas:write there (the peek endpoint's gate). */
export type CaBundleScope = { orgId: string; canPeek: boolean; canReadCas: boolean };

type Props = {
  id: string;
  value: string;
  onChange: (v: string) => void;
  /** Field label, for the controls' accessible names. */
  label?: string;
  placeholder?: string;
  disabled?: boolean;
  invalid?: boolean;
  /** Prefills Fetch's server (the form's own URL field). */
  url?: string;
  /** Without one, only paste and Upload are offered. */
  scope?: CaBundleScope;
};

const PEEK_DENIED = 'Needs the delivery:write or cas:write permission';

/** A multi-line PEM bundle with Upload, Fetch from server and From saved CA.
 * Every source appends the certificates the box doesn't already hold: a
 * bundle often needs a root and an intermediate from different places, and
 * appending never drops what was pasted. Clear the box to start over. */
export function CaBundleInput({ id, value, onChange, label = 'CA bundle', placeholder, disabled, invalid, url, scope }: Props) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [fetchOpen, setFetchOpen] = useState(false);
  const summary = useMemo(() => summarizeBundle(value), [value]);
  const add = (pem: string) => onChange(appendPem(value, pem));

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    const pem = fileBytesToPem(new Uint8Array(await file.arrayBuffer()));
    if (pem === null) setFileError(`${file.name} is not a PEM or DER certificate.`);
    else {
      setFileError(null);
      add(pem);
    }
  };

  return (
    <div className="grid min-w-0 gap-1.5">
      <Textarea
        id={id}
        rows={5}
        spellCheck={false}
        className="max-h-64 font-mono text-xs break-all"
        value={value}
        placeholder={placeholder ?? '-----BEGIN CERTIFICATE-----'}
        disabled={disabled}
        aria-invalid={invalid || undefined}
        onChange={(e) => onChange(e.target.value)}
      />
      {!disabled && (
        <div className="flex flex-wrap items-center gap-1.5">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button type="button" variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
                <Upload aria-hidden /> Upload
              </Button>
            </TooltipTrigger>
            <TooltipContent className="max-w-64">{help['caBundle.upload'].text}</TooltipContent>
          </Tooltip>
          <input
            ref={fileRef}
            type="file"
            accept=".pem,.crt,.cer,.der"
            aria-label={`Upload ${label}`}
            className="hidden"
            onChange={(e) => {
              void onFile(e.target.files?.[0]);
              e.target.value = '';
            }}
          />
          {scope && (
            <PermissionTip allowed={scope.canPeek} action="delivery:write" reason={PEEK_DENIED}>
              {scope.canPeek ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button type="button" variant="outline" size="sm" onClick={() => setFetchOpen(true)}>
                      <Globe aria-hidden /> Fetch from server
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-64">{help['caBundle.fetch'].text}</TooltipContent>
                </Tooltip>
              ) : (
                <Button type="button" variant="outline" size="sm" disabled>
                  <Globe aria-hidden /> Fetch from server
                </Button>
              )}
            </PermissionTip>
          )}
          {scope?.canReadCas && <SavedCaPicker orgId={scope.orgId} label={label} onPick={add} />}
        </div>
      )}
      <BundleSummary certs={summary.certs} problem={fileError ?? summary.problem} />
      {scope?.canPeek && fetchOpen && (
        <FetchChainDialog
          orgId={scope.orgId}
          url={url}
          onClose={() => setFetchOpen(false)}
          onAdd={(pems) => {
            add(pems.join(''));
            setFetchOpen(false);
          }}
        />
      )}
    </div>
  );
}

function BundleSummary({ certs, problem }: { certs: { cn: string; notAfter: Date | null }[]; problem?: string | null }) {
  if (certs.length === 0 && !problem) return null;
  const now = Date.now();
  return (
    <div className="grid gap-0.5 text-xs" aria-live="polite">
      {certs.length > 0 && (
        <p className="text-ink-muted">
          {certs.length} certificate{certs.length === 1 ? '' : 's'}
        </p>
      )}
      {certs.length > 0 && (
        <ul className="grid gap-0.5" aria-label="Certificates in the bundle">
          {certs.map((c, i) => {
            const expired = c.notAfter !== null && c.notAfter.getTime() < now;
            return (
              <li key={i} className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                <span className="min-w-0 truncate font-medium">{c.cn}</span>
                {c.notAfter && (
                  <span className={cn('shrink-0', expired ? 'text-failed' : 'text-ink-muted')}>
                    {expired ? 'expired' : 'expires'} {fmtDate(c.notAfter.toISOString())}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {problem && (
        <p role="alert" className="flex items-center gap-1">
          <TriangleAlert className="size-3.5 shrink-0 text-expiring" aria-hidden />
          {problem}
        </p>
      )}
    </div>
  );
}

function SavedCaPicker({ orgId, label, onPick }: { orgId: string; label: string; onPick: (pem: string) => void }) {
  const cas = useQuery(casQuery(orgId));
  const withBundle = (cas.data ?? []).filter((c) => c.trustBundlePem.trim() !== '');
  if (withBundle.length === 0) return null;
  return (
    <div className="flex min-w-0 items-center gap-1">
      <div className="w-44 min-w-0">
        <Combobox
          aria-label={`${label} from saved CA`}
          value={undefined}
          onChange={(v) => {
            const ca = withBundle.find((c) => c.id === v);
            if (ca) onPick(ca.trustBundlePem);
          }}
          options={withBundle.map((c) => ({ value: c.id, label: c.name }))}
          placeholder="From saved CA"
          emptyText="No match"
        />
      </div>
      <HelpTip id="caBundle.saved" />
    </div>
  );
}

/** Index of the default pick: the topmost CA certificate, else a lone self-signed one. */
function suggested(chain: TlsPeekCertificate[]): string[] {
  for (let i = chain.length - 1; i >= 0; i--) if (chain[i]!.isCa) return [String(i)];
  return chain.length === 1 && chain[0]!.selfSigned ? ['0'] : [];
}

function FetchChainDialog({ orgId, url, onClose, onAdd }: { orgId: string; url?: string; onClose: () => void; onAdd: (pems: string[]) => void }) {
  const peek = usePeekTls(orgId);
  const [server, setServer] = useState(url ?? '');
  const [picked, setPicked] = useState<string[]>([]);
  const result = peek.isSuccess ? peek.data : undefined;
  const chain = result?.ok ? result.chain : [];
  const error = peek.isError ? errorMessage(peek.error) : result && !result.ok ? result.error || 'Could not read the chain.' : undefined;

  const run = () => {
    if (server.trim() === '') return;
    peek.mutate({ url: server.trim() }, { onSuccess: (r) => setPicked(r.ok ? suggested(r.chain) : []) });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-1.5">
            Fetch from server <HelpTip id="caBundle.tofu" warning />
          </DialogTitle>
          <DialogDescription className="sr-only">Read the certificate chain a server presents and pick the certificates to trust.</DialogDescription>
        </DialogHeader>
        <form
          className="flex min-w-0 gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            run();
          }}
        >
          <Input
            aria-label="Server"
            className="min-w-0 flex-1 font-mono text-xs"
            value={server}
            onChange={(e) => setServer(e.target.value)}
            placeholder="host:443 or https://host"
            autoFocus
          />
          <Button type="submit" variant="outline" disabled={server.trim() === '' || peek.isPending}>
            {peek.isPending && <LoaderCircle className="animate-spin" aria-hidden />}
            Fetch
          </Button>
        </form>
        {error && (
          <p role="alert" className="flex items-start gap-1 text-xs">
            <CircleAlert className="mt-px size-3.5 shrink-0 text-failed" aria-hidden />
            <span className="min-w-0 break-words">{error}</span>
          </p>
        )}
        {chain.length > 0 && (
          <>
            <p className="flex items-center gap-1 text-xs text-ink-muted">
              {result?.verified ? (
                <>
                  <ShieldCheck className="size-3.5 shrink-0 text-valid" aria-hidden /> Verified by system roots; a CA bundle may not be needed.
                </>
              ) : (
                <>
                  <ShieldAlert className="size-3.5 shrink-0 text-expiring" aria-hidden /> Not verified by system roots.
                </>
              )}
            </p>
            <ToggleGroup.Root type="multiple" value={picked} onValueChange={setPicked} aria-label="Certificates to add" className="grid gap-2">
              {chain.map((c, i) => {
                const on = picked.includes(String(i));
                return (
                  <ToggleGroup.Item
                    key={c.sha256}
                    value={String(i)}
                    className={cn(
                      'grid min-w-0 gap-0.5 rounded-md border p-2.5 text-left text-xs transition-colors',
                      on ? 'border-primary bg-selected' : 'border-border bg-panel hover:bg-subtle',
                    )}
                  >
                    <span className="flex min-w-0 items-center gap-1.5">
                      <span className={cn('flex size-4 shrink-0 items-center justify-center rounded-sm border', on ? 'border-primary bg-primary text-on-primary' : 'border-border')}>
                        {on && <Check className="size-3" aria-hidden />}
                      </span>
                      <span className="min-w-0 truncate text-sm font-medium">{cnOfDn(c.subject)}</span>
                      {c.isCa && <Tag>CA</Tag>}
                      {c.selfSigned && <Tag>Self-signed</Tag>}
                    </span>
                    <span className="truncate text-ink-muted">Issued by {cnOfDn(c.issuer)}</span>
                    <span className="text-ink-muted">Expires {fmtDate(c.notAfter)}</span>
                    <span className="font-mono text-[11px] break-all text-ink-muted">SHA-256 {c.sha256}</span>
                  </ToggleGroup.Item>
                );
              })}
            </ToggleGroup.Root>
          </>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="button" disabled={picked.length === 0} onClick={() => onAdd(picked.map(Number).sort((a, b) => a - b).map((i) => chain[i]!.pem))}>
            {picked.length > 1 ? `Add ${picked.length} certificates` : 'Add certificate'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Tag({ children }: { children: string }) {
  return <span className="shrink-0 rounded-sm bg-subtle px-1 text-[11px] font-normal text-ink">{children}</span>;
}
