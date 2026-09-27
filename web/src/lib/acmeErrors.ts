export type AcmeExplain = { text: string; fix: string; href: string };

const HREF = 'certificates.md#troubleshooting';
const MAP: Record<string, Omit<AcmeExplain, 'href'> & { href?: string }> = {
  rateLimited: { text: 'The CA rate limit was reached.', fix: 'Wait until the retry time', href: 'certificates.md#rate-limits' },
  dns: { text: 'A DNS lookup failed during validation.', fix: 'Check the TXT record and delegation' },
  unauthorized: { text: 'The CA did not accept the proof of control.', fix: 'Check the verification rule for this name' },
  incorrectResponse: { text: 'The CA saw a different token or TXT value than expected.', fix: 'Check for stale records and propagation' },
  caa: { text: 'A CAA record forbids this CA for a name.', fix: "Add the CA's CAA record", href: 'certificates.md#caa' },
  connection: { text: 'The CA could not reach the validation target.', fix: 'Check the port 80/443 route and firewalls' },
  rejectedIdentifier: { text: 'The CA will not issue for this name.', fix: 'Remove the name or use another CA' },
  externalAccountRequired: { text: 'The CA requires external account binding.', fix: 'Add EAB to the CA' },
  accountDoesNotExist: { text: 'The ACME account is unknown to the CA.', fix: 'Register the account again' },
  badNonce: { text: 'A transient protocol error occurred.', fix: 'It retries automatically' },
  serverInternal: { text: 'The CA had an internal error.', fix: 'It retries automatically' },
  malformed: { text: 'The CA rejected the request as malformed.', fix: 'Open the raw log for the field' },
  orderNotReady: { text: 'The order was finalized before validation completed.', fix: 'It retries automatically' },
};

export function explainAcmeError(type?: string | null): AcmeExplain | null {
  if (!type) return null;
  const key = type.replace('urn:ietf:params:acme:error:', '');
  const hit = MAP[key];
  return hit ? { text: hit.text, fix: hit.fix, href: hit.href ?? HREF } : { text: `The CA returned ${key}.`, fix: 'Open the raw log for details', href: HREF };
}
