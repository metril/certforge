import { Card, CardBody } from '@/components/Card';
import { useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from '@tanstack/react-router';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import { authMethodsQuery, useLogin } from '@/api/queries/auth';
import { HelpTip } from '@/components/HelpTip';
import { Wordmark } from '@/components/Wordmark';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { oidcErrorMessage, ssoHref } from './oidcError';

function Alert({ id, children }: { id?: string; children: string }) {
  return (
    <p id={id} role="alert" className="flex items-center gap-1 text-xs">
      <CircleAlert className="size-3.5 text-failed" aria-hidden />
      {children}
    </p>
  );
}

export function LoginPage({ redirectTo, error: oidcError }: { redirectTo: string; error?: string }) {
  const router = useRouter();
  const login = useLogin();
  const methods = useQuery(authMethodsQuery);
  const sso = methods.data?.oidcEnabled === true;
  const [breakGlass, setBreakGlass] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await login.mutateAsync(password);
      router.history.replace(redirectTo);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? 'Wrong password.' : errorMessage(err));
    }
  }

  const form = (
    <form onSubmit={submit} aria-label="Local admin sign in" className="grid gap-6">
      <div className="grid gap-1.5">
        <div className="flex items-center gap-1.5">
          <Label htmlFor="password">Admin password</Label>
          <HelpTip id="login.password" />
        </div>
        <Input
          id="password"
          type="password"
          autoComplete="current-password"
          autoFocus={!sso}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-invalid={!!error}
          aria-describedby={error ? 'login-error' : undefined}
        />
        {error && <Alert id="login-error">{error}</Alert>}
      </div>
      <Button type="submit" variant={sso ? 'outline' : 'default'} disabled={!password || login.isPending}>
        {login.isPending ? 'Signing in…' : 'Sign in'}
      </Button>
    </form>
  );

  return (
    <main className="grid min-h-dvh place-items-center bg-surface px-4">
      <div className="grid w-full max-w-sm gap-6">
        <Wordmark />
        <Card>
          <CardBody className="grid gap-6">
        <h1 className="text-lg font-semibold">Sign in</h1>
        {oidcError && <Alert>{oidcErrorMessage(oidcError)}</Alert>}
        {sso ? (
          <>
            <div className="flex items-center gap-1.5">
              <Button asChild className="flex-1">
                <a href={ssoHref(redirectTo)}>Sign in with single sign-on</a>
              </Button>
              <HelpTip id="login.sso" />
            </div>
            <Collapsible open={breakGlass} onOpenChange={setBreakGlass} className="grid gap-4">
              <div className="flex items-center gap-1.5">
                <CollapsibleTrigger asChild>
                  <Button variant="ghost" size="sm" className="w-fit px-0 text-ink-muted">
                    Break-glass login
                  </Button>
                </CollapsibleTrigger>
                <HelpTip id="login.breakGlass" />
              </div>
              <CollapsibleContent>{form}</CollapsibleContent>
            </Collapsible>
          </>
        ) : (
          form
        )}
          </CardBody>
        </Card>
      </div>
    </main>
  );
}
