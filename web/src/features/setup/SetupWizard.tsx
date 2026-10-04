import { Card, CardBody } from '@/components/Card';
import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { CircleAlert, CircleCheck, CircleX, RotateCw, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { setupStatusQuery, useCompleteSetup } from '@/api/queries/auth';
import { readinessQuery } from '@/api/queries/health';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { Stepper } from '@/components/Stepper';
import { Wordmark } from '@/components/Wordmark';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SLUG_RE, toSlug } from './slug';

const STEPS = ['Admin password', 'Base URL', 'Encryption key', 'First organization'];

function isHttpUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

// Readiness check names -> what the person setting up sees.
const CHECK_LABEL: Record<string, string> = { kek: 'Encryption key', database: 'Database' };

export function SetupWizard() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const complete = useCompleteSetup();
  const [step, setStep] = useState(0);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [token, setToken] = useState('');
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [baseUrl, setBaseUrl] = useState(() => window.location.origin);
  const [orgName, setOrgName] = useState('');
  const [orgSlug, setOrgSlug] = useState('');
  const [slugTouched, setSlugTouched] = useState(false);
  const [finishError, setFinishError] = useState<string | null>(null);
  const status = useQuery(setupStatusQuery);
  const tokenRequired = status.data?.tokenRequired === true;
  const readiness = useQuery({ ...readinessQuery, enabled: step === 2, refetchInterval: false });

  // Step 2 has no field: focus its heading so each step starts with focus inside it.
  const kekHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (step === 2) kekHeading.current?.focus();
  }, [step]);

  const cleanBase = baseUrl.trim().replace(/\/+$/, '');
  // Fix round 1 (controller ruling): gate specifically on the kek check, not
  // overall readiness.ok, and fail closed if the key is missing entirely.
  const kekOk = readiness.data?.checks.find((c) => c.name === 'kek')?.ok === true;
  // Only checks that are not passing are listed; a missing kek check counts as failing.
  const failing: { name: string; message?: string }[] = readiness.data
    ? [...readiness.data.checks.filter((c) => !c.ok), ...(readiness.data.checks.some((c) => c.name === 'kek') ? [] : [{ name: 'kek' }])]
    : [];
  const canNext = [
    password.length >= 12 && confirm === password && (!tokenRequired || token !== ''),
    isHttpUrl(cleanBase),
    kekOk,
    orgName.trim() !== '' && SLUG_RE.test(orgSlug),
  ][step];

  async function finish() {
    setFinishError(null);
    setTokenError(null);
    try {
      await complete.mutateAsync({ adminPassword: password, orgName: orgName.trim(), orgSlug, baseUrl: cleanBase, ...(tokenRequired ? { setupToken: token } : {}) });
      toast.success('Setup complete');
      await navigate({ to: '/o/$org/issuers/cas', params: { org: orgSlug }, search: { edit: 'new' } });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // Fix round 1: another session finished setup first. setup-status has
        // staleTime: Infinity and no active observer here, so `invalidateQueries`
        // alone marks it stale without changing what the next `ensureQueryData`
        // call in a route guard returns (it only refetches on a cache miss);
        // `setQueryData` makes /login's and /setup's guards see needsSetup:
        // false immediately, without an extra round trip to a 409ing endpoint.
        qc.setQueryData(setupStatusQuery.queryKey, { needsSetup: false, tokenRequired: false });
        await qc.invalidateQueries({ queryKey: setupStatusQuery.queryKey });
        toast.error('Setup was already completed. Sign in instead.');
        await navigate({ to: '/login' });
        return;
      }
      if (err instanceof ApiError && err.status === 401) {
        // The setup token was missing or wrong: send the person back to its field.
        setTokenError('The setup token was not accepted.');
        setStep(0);
        return;
      }
      setFinishError(errorMessage(err));
    }
  }

  return (
    <main className="min-h-dvh bg-surface px-4 py-10">
      <div className="mx-auto grid max-w-xl gap-8">
        <Wordmark />
        <Stepper steps={STEPS} current={step} onSelect={setStep} />
        <Card>
        <CardBody>
        <form
          className="grid gap-5"
          onSubmit={(e) => {
            e.preventDefault();
            if (!canNext) return;
            if (step < 3) setStep(step + 1);
            else void finish();
          }}
        >
          {step === 0 && (
            <>
              {tokenRequired && (
                <Field id="setup-token" label="Setup token" help="setup.token" error={tokenError}>
                  <Input id="setup-token" type="password" autoComplete="off" autoFocus value={token} onChange={(e) => { setToken(e.target.value); setTokenError(null); }} />
                </Field>
              )}
              <Field id="admin-password" label="Admin password" help="setup.adminPassword"
                error={password && password.length < 12 ? '12 characters minimum' : null}>
                <Input id="admin-password" type="password" autoComplete="new-password" autoFocus={!tokenRequired} value={password} onChange={(e) => setPassword(e.target.value)} />
              </Field>
              <Field id="admin-confirm" label="Confirm password" error={confirm && confirm !== password ? 'Passwords differ' : null}>
                <Input id="admin-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              </Field>
            </>
          )}
          {step === 1 && (
            <div className="grid gap-1.5">
              <Field id="base-url" label="Base URL" help="setup.baseUrl" error={isHttpUrl(cleanBase) ? null : 'Enter a full URL, like https://certs.example.com'}>
                <Input id="base-url" autoFocus className="font-mono text-xs" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://certs.example.com" />
              </Field>
              {cleanBase === window.location.origin ? (
                <p className="flex items-center gap-1 text-xs">
                  <CircleCheck className="size-3.5 text-valid" aria-hidden />
                  Matches this browser
                </p>
              ) : (
                <p className="flex items-center gap-1 text-xs">
                  <TriangleAlert className="size-3.5 text-expiring" aria-hidden />
                  Differs from this browser's address
                </p>
              )}
              {/^http:\/\//i.test(cleanBase) && (
                <p className="flex items-center gap-1 text-xs">
                  <TriangleAlert className="size-3.5 text-expiring" aria-hidden />
                  https is recommended: sign-in cookies and API keys cross this address.
                </p>
              )}
            </div>
          )}
          {step === 2 && (
            <section className="grid gap-3" aria-live="polite">
              <div className="flex items-center gap-1.5">
                <h2 ref={kekHeading} tabIndex={-1} className="text-base font-semibold outline-none">
                  Encryption key
                </h2>
                <HelpTip id="setup.kek" />
              </div>
              {readiness.isPending && <p className="text-ink-muted">Checking…</p>}
              {readiness.isError && (
                <p className="flex items-center gap-1 text-xs">
                  <CircleX className="size-3.5 text-failed" aria-hidden />
                  {errorMessage(readiness.error)}
                </p>
              )}
              {failing.length > 0 && (
                <ul className="grid gap-1.5">
                  {failing.map((c) => (
                    <li key={c.name} className="flex items-center gap-2">
                      <CircleX className="size-4 text-failed" aria-hidden />
                      <span>{CHECK_LABEL[c.name] ?? c.name}</span>
                      {c.message && <span className="text-ink-muted">{c.message}</span>}
                    </li>
                  ))}
                </ul>
              )}
              {(readiness.isError || (readiness.data && !kekOk)) && (
                <Button type="button" variant="outline" className="w-fit" disabled={readiness.isFetching} onClick={() => void readiness.refetch()}>
                  <RotateCw className="size-4" aria-hidden />
                  {readiness.isFetching ? 'Checking…' : 'Check again'}
                </Button>
              )}
            </section>
          )}
          {step === 3 && (
            <>
              <Field id="org-name" label="Organization">
                <Input
                  id="org-name"
                  autoFocus
                  value={orgName}
                  placeholder="Acme"
                  onChange={(e) => {
                    setOrgName(e.target.value);
                    if (!slugTouched) setOrgSlug(toSlug(e.target.value));
                  }}
                />
              </Field>
              <Field id="org-slug" label="Slug" help="setup.orgSlug" error={orgSlug && !SLUG_RE.test(orgSlug) ? 'Lowercase letters, digits, and hyphens' : null}>
                <Input
                  id="org-slug"
                  className="font-mono text-xs"
                  value={orgSlug}
                  placeholder="acme"
                  onChange={(e) => {
                    setSlugTouched(true);
                    setOrgSlug(e.target.value);
                  }}
                />
              </Field>
              {finishError && (
                <p role="alert" className="flex items-center gap-1 text-xs">
                  <CircleAlert className="size-3.5 text-failed" aria-hidden />
                  {finishError}
                </p>
              )}
            </>
          )}
          <div className="flex gap-2">
            {step > 0 && (
              <Button type="button" variant="outline" onClick={() => setStep(step - 1)}>
                Back
              </Button>
            )}
            <Button type="submit" disabled={!canNext || complete.isPending}>
              {step < 3 ? 'Next' : complete.isPending ? 'Finishing…' : 'Finish setup'}
            </Button>
          </div>
        </form>
        </CardBody>
        </Card>
      </div>
    </main>
  );
}
