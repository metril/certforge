const MESSAGES: Record<string, string> = {
  oidc_disabled: 'Single sign-on is not configured.',
  oidc_state: 'The sign-in expired or was interrupted. Try again.',
  oidc_denied: 'The identity provider refused the sign-in.',
  user_disabled: 'Your account is disabled. Ask an administrator.',
};

/** One-line message for a /login?error= code from the OIDC callback. */
export function oidcErrorMessage(code: string): string {
  return MESSAGES[code] ?? 'Single sign-on failed. Try again.';
}

/** Where the single sign-on button points; a full-page navigation. */
export function ssoHref(next: string): string {
  return `/api/v1/auth/oidc/start?next=${encodeURIComponent(next)}`;
}
