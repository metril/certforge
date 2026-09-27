import { useMemo, useReducer, useState, type Dispatch } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { CircleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { useCreateCertificate, useUpdateCertificate } from '@/api/queries/certificates';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { Certificate, VerificationRule } from '@/api/types';
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
import { canContinueNames, fromCertificate, initialWizard, toCertificateInput, wizardReducer, type WizardAction } from './state';
import { SummaryRail } from './SummaryRail';
import { VerificationStep } from './VerificationStep';

const STEPS = ['Names', 'Verification', 'Options', 'Review'];
const NAMES_STEP = 0;
const VERIFICATION_STEP = 1;
const OPTIONS_STEP = 2;
const REVIEW_STEP = 3;

const OPTIONS_KEYS = new Set<string>(ISSUANCE_FIELDS.filter((f) => f.key !== 'verificationRules').map((f) => f.key));

// fieldOfTitle (shared, @/api/errors) reads a 422's title, "Invalid <field>"
// or "Invalid <field>.<sub>" (mapErr/unprocessable in internal/api and
// internal/issuance). stepForField below maps that field to a step itself
// rather than reusing issuanceFields.tsx's fieldFromTitle→FieldKey mapping,
// since that helper matches 'verificationRules' as an *overrides* field
// (Options step) while here the same title names the certificate's own
// rules (Verification step).

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

// Fix round 1 (review, Important #1): mirrors the server's own reissue
// check exactly — internal/issuance/store_certs.go's UpdateCertificate
// compares `cur.Names()` (`[commonName, ...sans]`, already normalised by a
// prior NormalizeNames) against the freshly `NormalizeNames`d submission,
// with `slices.Equal` (ordered). A plain set comparison of `state.names`
// (the previous version of this function) missed a common-name-only change
// (the set doesn't change, only which element leads) and never built the
// `[cn, ...sans]` order the server actually compares. `NormalizeNames`
// itself (internal/issuance/names.go): lowercase, trim, drop a trailing
// dot, drop empties, de-duplicate keeping the first occurrence.
function normalizeNames(commonName: string | null | undefined, names: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of [commonName ?? '', ...names]) {
    const n = raw.trim().replace(/\.$/, '').toLowerCase();
    if (!n || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

function namesEqual(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((n, i) => n === b[i]);
}

function rulesEqual(a: VerificationRule[], b: VerificationRule[]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function CertificateWizard({ from, edit }: { from?: Certificate; edit?: Certificate }) {
  const org = useOrg();
  const navigate = useNavigate();
  const source = edit ?? from;
  const [state, rawDispatch] = useReducer(wizardReducer, source, (c) =>
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

  const originalNames = useMemo(() => (edit ? normalizeNames(edit.commonName, edit.sans) : []), [edit]);
  const currentNames = useMemo(() => normalizeNames(state.cn, state.names), [state.cn, state.names]);
  const namesChanged = !!edit && !namesEqual(currentNames, originalNames);
  const originalRules = edit?.verificationRules ?? [];

  // Fix round 1 (review, Important #2): a 422/500 banner that only clears
  // on the *next* submit attempt stays on screen through every subsequent
  // edit, even once the field it named no longer applies. Any dispatch (the
  // user changing something) or step navigation clears it instead.
  const dispatch: Dispatch<WizardAction> = (action) => {
    setSubmitError(null);
    rawDispatch(action);
  };

  function goToStep(i: number) {
    setSubmitError(null);
    setStep(i);
  }

  async function submit() {
    setSubmitError(null);
    try {
      const cert = edit ? await update.mutateAsync(toCertificateInput(state)) : await create.mutateAsync(toCertificateInput(state));
      // Fix round 1 (review, Important #3): saving an edit that touched
      // nothing about verification (only, say, the key type) must not
      // silently overwrite a credential the user picked for an unrelated
      // certificate's rule sharing the same zone since this one was loaded.
      if (!edit || !rulesEqual(originalRules, state.rules)) rememberFromRules(state.rules);
      toast.success(edit ? `Saved ${cert.name}` : `Issuing ${cert.name}`);
      // Fix round 1 (take-now #6): an edit that didn't change names doesn't
      // queue a new issuance (server: "other changes apply at the next
      // renewal"), so there's no live attempt to land on — go to Overview.
      const tab = edit && !namesChanged ? 'overview' : 'attempts';
      await navigate({ to: '/o/$org/certificates/$id/$tab', params: { org: org.slug, id: cert.id, tab } });
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
      <div className="grid gap-8 md:grid-cols-[minmax(0,1fr)_280px]">
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
