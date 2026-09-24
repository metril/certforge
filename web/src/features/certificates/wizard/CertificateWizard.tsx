import { useMemo, useReducer, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { CircleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { useCreateCertificate, useUpdateCertificate } from '@/api/queries/certificates';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { Certificate } from '@/api/types';
import { PageHeader } from '@/components/PageHeader';
import { Stepper } from '@/components/Stepper';
import { Button } from '@/components/ui/button';
import { ISSUANCE_FIELDS, type FieldKey } from '@/features/settings/issuanceFields';
import { inheritedFrom, verificationReady } from '@/lib/coverage';
import { rememberFromRules } from '@/lib/lastCredential';
import { useOrg } from '@/lib/org';
import { NamesStep } from './NamesStep';
import { OptionsStep } from './OptionsStep';
import { ReviewStep } from './ReviewStep';
import { canContinueNames, fromCertificate, initialWizard, toCertificateInput, wizardReducer } from './state';
import { SummaryRail } from './SummaryRail';
import { VerificationStep } from './VerificationStep';

const STEPS = ['Names', 'Verification', 'Options', 'Review'];
const NAMES_STEP = 0;
const VERIFICATION_STEP = 1;
const OPTIONS_STEP = 2;
const REVIEW_STEP = 3;

const OPTIONS_KEYS = new Set<string>(ISSUANCE_FIELDS.filter((f) => f.key !== 'verificationRules').map((f) => f.key));

// A 422's title is "Invalid <field>" or "Invalid <field>.<sub>" (mapErr /
// unprocessable in internal/api and internal/issuance) — the same shape
// issuanceFields.tsx's fieldFromTitle reads, but that helper also matches
// 'verificationRules' as an *overrides* field (Options step); here the same
// title names the certificate's own rules (Verification step), so this
// wizard maps titles itself rather than reusing it.
function fieldOfTitle(title?: string): string | null {
  if (!title) return null;
  const name = title.replace(/^Invalid\s+/, '').split('.')[0];
  return name || null;
}

/** Which step owns a 422's named field (controller ruling: "a 422 lands the
 * user back on the step that owns the named field with the problem detail
 * inline"). `name` is edited on Review (its only editor); an unmapped field
 * (or a non-422 failure) also lands on Review, where the banner shows. */
function stepForField(field: string | null): number {
  if (field === 'sans' || field === 'commonName') return NAMES_STEP;
  if (field === 'verificationRules') return VERIFICATION_STEP;
  if (field && OPTIONS_KEYS.has(field as FieldKey)) return OPTIONS_STEP;
  return REVIEW_STEP;
}

export function CertificateWizard({ from, edit }: { from?: Certificate; edit?: Certificate }) {
  const org = useOrg();
  const navigate = useNavigate();
  const source = edit ?? from;
  const [state, dispatch] = useReducer(wizardReducer, source, (c) =>
    c ? (edit ? fromCertificate(c) : { ...fromCertificate(c), name: `${c.name} copy` }) : initialWizard,
  );
  const [step, setStep] = useState(0);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const eff = useQuery(effectiveDefaultsQuery(org.id)).data;
  const inherited = useMemo(() => inheritedFrom(eff), [eff]);
  const create = useCreateCertificate(org.id);
  const update = useUpdateCertificate(org.id, edit?.id ?? '');
  const saving = edit ? update : create;

  const namesOk = canContinueNames(state);
  const verOk = namesOk && verificationReady(state.names, state.rules, inherited);
  const reachable = [true, namesOk, verOk, verOk];

  // fromCertificate's own SANs normalisation (apex folded in when missing)
  // means comparing against the *loaded* names, not the raw API sans/cn,
  // so an unrelated field edit never falsely reads as a name change.
  const originalNames = useMemo(() => (edit ? fromCertificate(edit).names : []), [edit]);
  const namesChanged = !!edit && (state.names.length !== originalNames.length || state.names.some((n) => !originalNames.includes(n)));

  function goToStep(i: number) {
    setStep(i);
  }

  async function submit() {
    setSubmitError(null);
    try {
      const cert = edit ? await update.mutateAsync(toCertificateInput(state)) : await create.mutateAsync(toCertificateInput(state));
      rememberFromRules(state.rules);
      toast.success(edit ? `Saved ${cert.name}` : `Issuing ${cert.name}`);
      await navigate({ to: '/o/$org/certificates/$id/$tab', params: { org: org.slug, id: cert.id, tab: 'attempts' } });
    } catch (e) {
      const field = e instanceof ApiError && e.status === 422 ? fieldOfTitle(e.problem.title) : null;
      goToStep(stepForField(field));
      setSubmitError(errorMessage(e));
    }
  }

  return (
    <>
      <PageHeader title={edit ? `Edit ${edit.name}` : from ? `Duplicate ${from.name}` : 'New certificate'} />
      {namesChanged && <p className="mb-4 text-xs text-ink-muted">Changing names will issue a new certificate.</p>}
      <div className="mb-6">
        <Stepper steps={STEPS} current={step} onSelect={goToStep} canSelect={(i) => reachable[i]!} />
      </div>
      <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="grid min-w-0 content-start gap-6">
          {submitError && (
            <p role="alert" className="flex items-center gap-1.5 text-sm text-failed">
              <CircleAlert className="size-4 shrink-0" aria-hidden />
              {submitError}
            </p>
          )}
          {step === 0 && <NamesStep state={state} dispatch={dispatch} />}
          {step === 1 && <VerificationStep orgId={org.id} state={state} dispatch={dispatch} inherited={inherited} />}
          {step === 2 && <OptionsStep orgId={org.id} state={state} dispatch={dispatch} />}
          {step === 3 && <ReviewStep orgId={org.id} state={state} dispatch={dispatch} inherited={inherited} />}
          <div className="flex flex-wrap gap-2 border-t border-border pt-4">
            {step > 0 && (
              <Button variant="outline" onClick={() => goToStep(step - 1)}>
                Back
              </Button>
            )}
            {step < 3 && (
              <Button variant={step === 0 ? 'default' : 'outline'} disabled={!reachable[step + 1]} onClick={() => goToStep(step + 1)}>
                {step === 2 ? 'Review' : 'Next'}
              </Button>
            )}
            {step >= 1 && (
              <Button disabled={!verOk || saving.isPending} onClick={() => void submit()}>
                {saving.isPending ? (edit ? 'Saving…' : 'Issuing…') : edit ? 'Save changes' : 'Issue certificate'}
              </Button>
            )}
          </div>
        </div>
        <SummaryRail orgId={org.id} state={state} inherited={inherited} />
      </div>
    </>
  );
}
