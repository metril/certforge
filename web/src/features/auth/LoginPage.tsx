import { useState, type FormEvent } from 'react';
import { useRouter } from '@tanstack/react-router';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import { useLogin } from '@/api/queries/auth';
import { HelpTip } from '@/components/HelpTip';
import { Wordmark } from '@/components/Wordmark';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export function LoginPage({ redirectTo }: { redirectTo: string }) {
  const router = useRouter();
  const login = useLogin();
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

  return (
    <main className="grid min-h-dvh place-items-center bg-surface px-4">
      <form onSubmit={submit} aria-labelledby="login-title" className="grid w-full max-w-sm gap-6">
        <Wordmark />
        <h1 id="login-title" className="text-lg font-semibold">
          Sign in
        </h1>
        <div className="grid gap-1.5">
          <div className="flex items-center gap-1.5">
            <Label htmlFor="password">Admin password</Label>
            <HelpTip id="login.password" />
          </div>
          <Input
            id="password"
            type="password"
            autoComplete="current-password"
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-invalid={!!error}
            aria-describedby={error ? 'login-error' : undefined}
          />
          {error && (
            <p id="login-error" role="alert" className="flex items-center gap-1 text-xs">
              <CircleAlert className="size-3.5 text-failed" aria-hidden />
              {error}
            </p>
          )}
        </div>
        <Button type="submit" disabled={!password || login.isPending}>
          {login.isPending ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    </main>
  );
}
