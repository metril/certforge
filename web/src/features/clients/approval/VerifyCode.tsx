import { cn } from '@/lib/utils';

/** ABCDEFGH -> ABCD-EFGH. The server sends 8 characters; the agent logs the hyphenated form. */
export function formatVerifyCode(code: string): string {
  const c = code.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  return c.length === 8 ? `${c.slice(0, 4)}-${c.slice(4)}` : c;
}

/** The code the admin compares against the agent log. The alphabet is base32
 * without 0/1/8/9, so no two characters look alike. The visual form is
 * aria-hidden and a spelled-out copy is announced instead. */
export function VerifyCode({ code, className }: { code: string; className?: string }) {
  const shown = formatVerifyCode(code);
  return (
    <>
      <span aria-hidden data-testid="verify-code" className={cn('font-mono text-3xl font-semibold tracking-[0.2em] sm:text-4xl', className)}>
        {shown}
      </span>
      <span className="sr-only">Verification code: {shown.replace('-', ' ').split('').join(' ')}</span>
    </>
  );
}
