import { useState, type ReactNode } from 'react';
import { ChevronLeft, CircleAlert, CircleOff, Download, Import, Pencil, RotateCw } from 'lucide-react';
import { Link, Navigate, useNavigate } from '@tanstack/react-router';
import { toast } from 'sonner';
import { useRotateCa } from '@/api/queries/cas';
import { UNCHANGED, type CA } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { CopyField } from '@/components/CopyField';
import { HelpTip, HelpTipBody } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { ValidityBar } from '@/components/ValidityBar';
import { Button } from '@/components/ui/button';
import { PageHeader } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK } from '@/components/TabLabel';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { caTone, KIND_ICON, KIND_LABEL, kindOf } from '@/lib/caKinds';
import { help } from '@/lib/help';
import { safeName, saveBlob } from '@/lib/download';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { fmtDate, relDays } from '@/lib/time';
import { cn } from '@/lib/utils';
import { AdcsTestButton, AdcsTestDialog } from './AdcsTestDialog';
import { adcsProbeRequest } from './caBody';

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
type AdcsConfig = { template: string; cesUrl?: string; cepUrl: string; templateOid?: string; templateKeyTypes?: string[] };

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

export type CaTab = 'overview' | 'crl';
const TAB_LABEL: Record<CaTab, string> = { overview: 'Overview', crl: 'CRL' };

type Props = { orgId: string; orgSlug: string; ca: CA; tab: CaTab };

/** A private CA's page: issuing certificate and actions, plus a CRL tab for built-in CAs. Create / edit stays the CaSheet on the list. */
export function CaDetail({ orgId, orgSlug, ca, tab }: Props) {
  const me = useMe();
  const navigate = useNavigate();
  const canWrite = can(me, 'cas:write', orgId);
  const kind = kindOf(ca);
  const rotate = useRotateCa(orgId);
  const [confirmingRotate, setConfirmingRotate] = useState(false);
  const [testing, setTesting] = useState(false);

  const local = kind === 'localca' ? (ca.config as unknown as LocalConfig) : null;
  const vault = kind === 'vaultpki' ? (ca.config as unknown as VaultConfig) : null;
  const adcsCfg = kind === 'adcs' ? (ca.config as unknown as AdcsConfig) : null;
  const adcsRequest = adcsCfg ? adcsProbeRequest({ ...(ca.config as Record<string, unknown>), password: UNCHANGED }, ca.id) : null;

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

  const tabs = (kind === 'localca' ? (['overview', 'crl'] as const) : (['overview'] as const)).map((x) => (
    <Link key={x} to="/o/$org/issuers/cas/$id/$tab" params={{ org: orgSlug, id: ca.id, tab: x }} className={TAB_LINK} activeProps={TAB_ACTIVE}>
      {TAB_LABEL[x]}
    </Link>
  ));
  if (tab === 'crl' && kind !== 'localca') return <Navigate to="/o/$org/issuers/cas/$id/$tab" params={{ org: orgSlug, id: ca.id, tab: 'overview' }} replace />;

  return (
    <>
      <Link to="/o/$org/issuers/cas" params={{ org: orgSlug }} className="mb-2 inline-flex items-center gap-1 text-sm text-ink-muted hover:text-ink">
        <ChevronLeft className="size-4" aria-hidden />
        Certificate authorities
      </Link>
      <PageHeader
        title={ca.name}
        tabs={tabs}
        tabsLabel="CA sections"
        actions={
          <PermissionTip allowed={canWrite} action="cas:write">
            <Button type="button" variant="outline" size="sm" disabled={!canWrite} onClick={() => void navigate({ to: '/o/$org/issuers/cas', params: { org: orgSlug }, search: { edit: ca.id } })}>
              <Pencil className="size-3.5" aria-hidden />
              Edit
            </Button>
          </PermissionTip>
        }
      >
        <div className="flex items-center gap-2">
          <ToneChip tone="neutral" icon={KIND_ICON[kind]} label={KIND_LABEL[kind]} />
        </div>
      </PageHeader>
      <div className="grid gap-5">
        {tab === 'overview' && (
          <>
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
            {adcsCfg && (
              <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
                <Fact label="Template">
                  <span className="font-mono text-xs">{adcsCfg.template}</span>
                </Fact>
                <Fact label="CES URL">
                  <span className="break-all font-mono text-xs">{adcsCfg.cesUrl ?? '–'}</span>
                </Fact>
                <Fact label="Revocation">Manual in AD CS</Fact>
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
          {kind === 'adcs' && (
            <section className="flex items-center gap-1.5">
              <AdcsTestButton canWrite={canWrite} request={adcsRequest} onClick={() => setTesting(true)} />
              <HelpTip id="ca.adcsTest" />
            </section>
          )}
          {kind === 'localca' && (
            <section className="flex items-center gap-1.5">
              <RotateButton canWrite={canWrite} imported={!!local?.imported} onClick={() => setConfirmingRotate(true)} />
              <HelpTip id="ca.rotate" />
            </section>
          )}
          </>
        )}
        {tab === 'crl' && (
          <>
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
          </>
        )}
      </div>
      {testing && adcsRequest && <AdcsTestDialog orgId={orgId} name={ca.name} request={adcsRequest} onOpenChange={setTesting} />}
      <ConfirmDestructive
        open={confirmingRotate}
        onOpenChange={setConfirmingRotate}
        title="Rotate issuing certificate?"
        consequence="New certificates use a new intermediate; existing ones stay valid."
        confirmText="Rotate"
        actionLabel="Rotate"
        onConfirm={() => rotate.mutateAsync(ca.id)}
      />
    </>
  );
}
