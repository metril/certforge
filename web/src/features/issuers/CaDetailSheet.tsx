import { useState, type ReactNode } from 'react';
import { CircleAlert, CircleOff, Download, Import, Pencil, RotateCw } from 'lucide-react';
import { Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import { useRotateCa } from '@/api/queries/cas';
import type { CA } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { CopyField } from '@/components/CopyField';
import { HelpTip, HelpTipBody } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { ValidityBar } from '@/components/ValidityBar';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { caTone, KIND_ICON, KIND_LABEL, kindOf } from '@/lib/caKinds';
import { help } from '@/lib/help';
import { safeName, saveBlob } from '@/lib/download';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { fmtDate, relDays } from '@/lib/time';
import { cn } from '@/lib/utils';

type Subject = { commonName: string; organization?: string; country?: string };
type RetiredIssuer = { pem: string; notAfter: string; serial: string; crlUrl?: string };
// Batch 1 review: Go's `Retired []retiredIssuer` has no `omitempty` and a
// freshly created (never rotated) CA leaves it unset, so the wire value is
// `null`, not `[]` — every fixture happened to carry an array already.
type LocalConfig = {
  subject: Subject;
  keyType: string;
  maxLeafDays: number;
  crl: boolean;
  imported: boolean;
  retired: RetiredIssuer[] | null;
  revokedCount: number;
};
type VaultConfig = { mount: string; role: string; ttl?: string };

/** A small label/value row for the fact panels below, the same shape as
 * ClientHeader.tsx's own local `Fact` (no shared export exists to reuse). */
function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="min-w-0 truncate">{children}</dd>
    </div>
  );
}

function RetiredChip({ retired, onCopy }: { retired: RetiredIssuer; onCopy: (url: string) => void }) {
  const disabled = !retired.crlUrl;
  const chip = (
    <button
      type="button"
      disabled={disabled}
      title={retired.serial}
      onClick={() => retired.crlUrl && onCopy(retired.crlUrl)}
      className={cn(
        'inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-sm border border-border bg-subtle px-2 text-xs font-semibold text-ink',
        disabled ? 'opacity-50' : 'hover:bg-accent',
      )}
    >
      <span className="font-mono">{retired.serial.slice(0, 8)}</span>
      <span className="font-normal text-ink-muted">until {fmtDate(retired.notAfter)}</span>
    </button>
  );
  if (!disabled) return chip;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          {chip}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
        <HelpTipBody entry={help['ca.retiredNoCrl']} />
      </TooltipContent>
    </Tooltip>
  );
}

/** Rotate is disabled two independent ways (task-3-brief): no `cas:write`
 * (PermissionTip's own tooltip), or an imported CA with no held root key
 * (`ca.rotateImported`). Both never need to combine in one render, so
 * whichever applies wins outright rather than stacking tooltips. */
function RotateButton({ canWrite, imported, onClick }: { canWrite: boolean; imported: boolean; onClick: () => void }) {
  const btn = (
    <Button type="button" variant="outline" disabled={!canWrite || imported} onClick={onClick}>
      <RotateCw className="size-3.5" aria-hidden />
      Rotate issuing certificate
    </Button>
  );
  if (!canWrite) return <PermissionTip allowed={false} action="cas:write">{btn}</PermissionTip>;
  if (imported) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} className="inline-flex">
            {btn}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
          <HelpTipBody entry={help['ca.rotateImported']} />
        </TooltipContent>
      </Tooltip>
    );
  }
  return btn;
}

type Props = { orgId: string; ca: CA; onEdit: () => void; onOpenChange: (open: boolean) => void };

export function CaDetailSheet({ orgId, ca, onEdit, onOpenChange }: Props) {
  const me = useMe();
  const canWrite = can(me, 'cas:write', orgId);
  const kind = kindOf(ca);
  const rotate = useRotateCa(orgId);
  const [confirmingRotate, setConfirmingRotate] = useState(false);

  const local = kind === 'localca' ? (ca.config as unknown as LocalConfig) : null;
  const vault = kind === 'vaultpki' ? (ca.config as unknown as VaultConfig) : null;

  async function copyRetiredCrl(url: string) {
    try {
      if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(url);
      toast.success('CRL URL copied');
    } catch {
      toast.error('Copy failed');
    }
  }

  function downloadTrustBundle() {
    const blob = new Blob([ca.trustBundlePem], { type: 'application/x-pem-file' });
    saveBlob(blob, `${safeName(ca.name)}-ca.pem`);
  }

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <SheetTitle>{ca.name}</SheetTitle>
              <ToneChip tone="neutral" icon={KIND_ICON[kind]} label={KIND_LABEL[kind]} />
            </div>
            <PermissionTip allowed={canWrite} action="cas:write">
              <Button type="button" variant="outline" size="sm" disabled={!canWrite} onClick={onEdit}>
                <Pencil className="size-3.5" aria-hidden />
                Edit
              </Button>
            </PermissionTip>
          </div>
          <SheetDescription className="sr-only">Private CA details</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          <section className="grid gap-2">
            <h3 className="text-sm font-semibold">Issuing certificate</h3>
            {ca.notBefore && ca.notAfter ? (
              <ValidityBar notBefore={ca.notBefore} notAfter={ca.notAfter} tone={caTone(ca.notAfter)} size="full" />
            ) : (
              // ValidityBar's own "full" legend already renders "Expires
              // <date> (<relDays>)" — this is only a fallback for the dates
              // it needs being absent, using the same formatter so the two
              // never show different day counts for the same instant
              // (batch 4 review: relTime floors, relDays doesn't).
              <div className="flex items-center gap-1.5 text-xs">
                <span>
                  Expires <span className="font-mono">{ca.notAfter ? fmtDate(ca.notAfter) : '–'}</span>
                  {ca.notAfter && <span className="text-ink-muted"> ({relDays(ca.notAfter)})</span>}
                </span>
                <HelpTip id="ca.expiry" />
              </div>
            )}
            {local && (
              <>
                <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
                  <Fact label="Subject">
                    <span className="font-mono text-xs">
                      CN={local.subject.commonName}
                      {local.subject.organization ? `, O=${local.subject.organization}` : ''}
                      {local.subject.country ? `, C=${local.subject.country}` : ''}
                    </span>
                  </Fact>
                  <Fact label="Key type">{local.keyType}</Fact>
                  <Fact label="Max leaf days">{local.maxLeafDays}</Fact>
                </dl>
                {local.imported && <ToneChip tone="neutral" icon={Import} label="Imported" />}
              </>
            )}
            {vault && (
              <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
                <Fact label="Mount">
                  <span className="font-mono text-xs">{vault.mount}</span>
                </Fact>
                <Fact label="Role">
                  <span className="font-mono text-xs">{vault.role}</span>
                </Fact>
                <Fact label="TTL">
                  <span className="font-mono text-xs">{vault.ttl ?? '–'}</span>
                </Fact>
              </dl>
            )}
          </section>

          <section className="grid gap-2">
            <h3 className="flex items-center gap-1.5 text-sm font-semibold">
              Trust bundle <HelpTip id="ca.trustBundle" />
            </h3>
            <Button type="button" variant="outline" size="sm" className="w-fit" onClick={downloadTrustBundle}>
              <Download className="size-3.5" aria-hidden />
              Download
            </Button>
          </section>

          {kind === 'localca' && local && (
            <section className="grid gap-2">
              <h3 className="flex items-center gap-1.5 text-sm font-semibold">
                CRL <HelpTip id="ca.crl" />
              </h3>
              {!local.crl ? (
                <ToneChip tone="neutral" icon={CircleOff} label="CRL off" />
              ) : ca.crlUrl ? (
                <CopyField value={ca.crlUrl} label="CRL URL" />
              ) : (
                <p className="flex items-center gap-1 text-xs">
                  <CircleAlert className="size-3.5 text-failed" aria-hidden />
                  Set the base URL in{' '}
                  <Link to="/settings/$section" params={{ section: 'general' }} className="underline underline-offset-2">
                    Settings → General
                  </Link>
                  .
                </p>
              )}
              <p className="text-xs text-ink-muted">
                Revoked <span className="font-mono">{local.revokedCount}</span>
              </p>
              {local.retired && local.retired.length > 0 && (
                <div className="grid gap-1.5">
                  <h4 className="flex items-center gap-1.5 text-xs font-semibold text-ink-muted">
                    Retired issuers <HelpTip id="ca.retired" />
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {local.retired.map((r) => (
                      <RetiredChip key={r.serial} retired={r} onCopy={copyRetiredCrl} />
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {kind === 'localca' && (
            <section className="flex items-center gap-1.5">
              <RotateButton canWrite={canWrite} imported={!!local?.imported} onClick={() => setConfirmingRotate(true)} />
              <HelpTip id="ca.rotate" />
            </section>
          )}
        </div>
      </SheetContent>
      <ConfirmDestructive
        open={confirmingRotate}
        onOpenChange={setConfirmingRotate}
        title="Rotate issuing certificate?"
        consequence="New certificates use a new intermediate; existing ones stay valid."
        confirmText="Rotate"
        actionLabel="Rotate"
        onConfirm={() => rotate.mutateAsync(ca.id)}
      />
    </Sheet>
  );
}
