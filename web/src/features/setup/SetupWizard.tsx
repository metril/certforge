import { Card, CardBody } from '@/components/Card';
import { useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { CircleAlert, CircleCheck, CircleX, RotateCw, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { setupStatusQuery, useCompleteSetup } from '@/api/queries/auth';
import { readinessQuery } from '@/api/queries/health';
import { HelpTip } from '@/components/HelpTip';
import { Stepper } from '@/components/Stepper';
import { Wordmark } from '@/components/Wordmark';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { HelpKey } from '@/lib/help';
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

function Row({ id, label, help, error, children }: { id: string; label: string; help?: HelpKey; error?: string | null; children: ReactNode }) {
  return (
    <div className="grid gap-1.5">
      <div className="flex items-center gap-1.5">
        <Label htmlFor={id}>{label}</Label>
        {help && <HelpTip id={help} />}
      </div>
      {children}
      {error && (
        <p className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          {error}
        </p>
      )}
    </div>
  );
}

export function SetupWizard() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const complete = useCompleteSetup();
  const [step, setStep] = useState(0);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [baseUrl, setBaseUrl] = useState(() => window.location.origin);
  const [orgName, setOrgName] = useState('');
  const [orgSlug, setOrgSlug] = useState('');
  const [slugTouched, setSlugTouched] = useState(false);
  const [finishError, setFinishError] = useState<string | null>(null);
  const readiness = useQuery({ ...readinessQuery, enabled: step === 2, refetchInterval: false });

  const cleanBase = baseUrl.trim().replace(/\/+$/, '');
  // Fix round 1 (controller ruling): gate specifically on the kek check, not
  // overall readiness.ok, and fail closed if the key is missing entirely.
  const kekOk = readiness.data?.checks.find((c) => c.name === 'kek')?.ok === true;
  const canNext = [
    password.length >= 12 && confirm === password,
    isHttpUrl(cleanBase),
    kekOk,
    orgName.trim() !== '' && SLUG_RE.test(orgSlug),
  ][step];

  async function finish() {
    setFinishError(null);
    try {
      await complete.mutateAsync({ adminPassword: password, orgName: orgName.trim(), orgSlug, baseUrl: cleanBase });
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
        qc.setQueryData(setupStatusQuery.queryKey, { needsSetup: false });
        await qc.invalidateQueries({ queryKey: setupStatusQuery.queryKey });
        toast.error('Setup was already completed. Sign in instead.');
        await navigate({ to: '/login' });
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
              <Row id="admin-password" label="Admin password" help="setup.adminPassword"
                error={password && password.length < 12 ? '12 characters minimum' : null}>
                <Input id="admin-password" type="password" autoComplete="new-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
              </Row>
              <Row id="admin-confirm" label="Confirm password" error={confirm && confirm !== password ? 'Passwords differ' : null}>
                <Input id="admin-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              </Row>
            </>
          )}
          {step === 1 && (
            <Row id="base-url" label="Base URL" help="setup.baseUrl" error={isHttpUrl(cleanBase) ? null : 'Enter a full URL, like https://certs.example.com'}>
              <Input id="base-url" className="font-mono text-xs" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://certs.example.com" />
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
            </Row>
          )}
          {step === 2 && (
            <section className="grid gap-3" aria-live="polite">
              <div className="flex items-center gap-1.5">
                <h2 className="text-base font-semibold">Encryption key</h2>
                <HelpTip id="setup.kek" />
              </div>
              {readiness.isPending && <p className="text-ink-muted">Checking…</p>}
              {readiness.isError && (
                <p className="flex items-center gap-1 text-xs">
                  <CircleX className="size-3.5 text-failed" aria-hidden />
                  {errorMessage(readiness.error)}
                </p>
              )}
              {readiness.data && (
                <ul className="grid gap-1.5">
                  {(readiness.data.checks.length ? readiness.data.checks : [{ name: 'server', ok: readiness.data.ok }]).map((c) => (
                    <li key={c.name} className="flex items-center gap-2">
                      {c.ok ? <CircleCheck className="size-4 text-valid" aria-hidden /> : <CircleX className="size-4 text-failed" aria-hidden />}
                      <span className="font-mono text-xs">{c.name}</span>
                      {'message' in c && c.message && <span className="text-ink-muted">{c.message}</span>}
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
              <Row id="org-name" label="Organization">
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
              </Row>
              <Row id="org-slug" label="Slug" help="setup.orgSlug" error={orgSlug && !SLUG_RE.test(orgSlug) ? 'Lowercase letters, digits, and hyphens' : null}>
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
              </Row>
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
