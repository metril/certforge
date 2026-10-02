import { Card, CardBody } from '@/components/Card';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert, CircleCheck } from 'lucide-react';
import { authMethodsQuery } from '@/api/queries/auth';
import { useTestAuthentication } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import type { AuthenticationTestResult } from '@/api/types';
import { CopyField } from '@/components/CopyField';
import { Field } from '@/components/Field';
import { Button } from '@/components/ui/button';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { GroupMappings } from './GroupMappings';
import { SchemaSection } from './SchemaSection';

function TestResult({ result }: { result: AuthenticationTestResult }) {
  return (
    <p role="status" className="flex items-center gap-1.5 text-sm">
      {result.ok ? <CircleCheck className="size-4 text-valid" aria-hidden /> : <CircleAlert className="size-4 text-failed" aria-hidden />}
      {result.ok ? `Issuer reachable, ${result.keys ?? 0} signing keys found.` : (result.detail ?? 'Test failed.')}
    </p>
  );
}

export function AuthenticationSection() {
  // Controller ruling B4: the redirect URI is the server's own effective
  // base URL (general.baseUrl, else CF_BASE_URL) plus the callback path,
  // never window.location — a reverse proxy or a different hostname per
  // visitor would otherwise show the wrong value.
  const me = useMe();
  // SchemaSection (Task 6) stopped gating `actions` on settings:write itself
  // (Vault's own Test connection needs to stay visible-but-disabled for a
  // non-writer) — this section keeps its own pre-5B behavior of hiding Test
  // connection entirely for a viewer.
  const canWrite = can(me, 'settings:write');
  const methods = useQuery(authMethodsQuery);
  const test = useTestAuthentication();
  const [result, setResult] = useState<AuthenticationTestResult | null>(null);

  async function runTest(issuer: string) {
    setResult(null);
    try {
      setResult(await test.mutateAsync(issuer));
    } catch (e) {
      setResult({ ok: false, detail: errorMessage(e) });
    }
  }

  return (
    <div className="grid max-w-[720px] gap-8">
      {methods.data && (
        <Card>
          <CardBody>
            <Field id="auth-redirect" label="Redirect URI" help="auth.redirectUri">
              <CopyField value={methods.data.oidcCallbackUrl} label="redirect URI" />
            </Field>
          </CardBody>
        </Card>
      )}
      <SchemaSection
        section="authentication"
        actions={(value) =>
          canWrite ? (
            <Button type="button" variant="outline" disabled={!value.issuer || test.isPending} onClick={() => void runTest(String(value.issuer))}>
              {test.isPending ? 'Testing…' : 'Test connection'}
            </Button>
          ) : null
        }
      />
      {result && <TestResult result={result} />}
      <GroupMappings />
    </div>
  );
}
