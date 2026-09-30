import { useEffect, useState } from 'react';
import { CircleCheck, CircleX, Clock, Send } from 'lucide-react';
import { testSmtp } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import type { DeliveryResult } from '@/api/types';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';

// DeliveryResult.status is the full DeliveryStatus enum though an inline
// test never actually returns "pending" (schema.d.ts's own comment); kept
// exhaustive without ever being rendered, same precedent as ChannelTest's
// own RESULT_META (Task 3).
const RESULT_META = {
  pending: { label: 'Pending', tone: 'pending' as const, icon: Clock },
  delivered: { label: 'Delivered', tone: 'valid' as const, icon: CircleCheck },
  failed: { label: 'Failed', tone: 'failed' as const, icon: CircleX },
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Sends a test email through the saved SMTP section (Task 6 brief), the
 * SchemaSection `actions` render-prop for the Email (SMTP) section. `value`
 * is the section's live (possibly unsaved) draft; `dirty` says whether it
 * differs from the saved section. Send test email always exercises the
 * *saved* config (global constraints, "Tests against unsaved drafts"), so
 * it's disabled while dirty and while the saved host is empty — `value.host`
 * IS the saved host whenever `dirty` is false, since `value` is then the
 * saved section itself. `to` lives only in this component's own state,
 * cleared on unmount like every other never-cached test result (Task 3's
 * ChannelTest, Vault's own Test connection).
 */
export function SmtpTest({ value, dirty }: { value: Record<string, unknown>; dirty: boolean }) {
  const me = useMe();
  const canWrite = can(me, 'settings:write');
  const [to, setTo] = useState('');
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<DeliveryResult | null>(null);
  const hostMissing = !value.host;

  // Cleared on any draft change, keyed on its content (not a fresh object
  // reference — SchemaSection's `value` is a new `withSecretSentinels`
  // object on every render, even a background refetch with no actual edit).
  const signature = JSON.stringify(value);
  useEffect(() => setResult(null), [signature]);

  async function run() {
    setTesting(true);
    try {
      setResult(await testSmtp(to));
    } catch (e) {
      setResult({ status: 'failed', error: errorMessage(e), durationMs: 0 });
    } finally {
      setTesting(false);
    }
  }

  const disabled = testing || !EMAIL_RE.test(to) || dirty || hostMissing || !canWrite;
  const allowed = canWrite && !dirty && !hostMissing;
  const reason = !canWrite ? undefined : dirty ? help['smtp.testSaved'].text : hostMissing ? help['smtp.needsHost'].text : undefined;
  const meta = result ? RESULT_META[result.status] : undefined;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Label htmlFor="smtp-test-to">Send to</Label>
      <Input
        id="smtp-test-to"
        type="email"
        placeholder="you@example.com"
        className="h-9 w-56"
        value={to}
        onChange={(e) => setTo(e.target.value)}
      />
      <PermissionTip allowed={allowed} action="settings:write" reason={reason}>
        <Button type="button" variant="outline" disabled={disabled} onClick={() => void run()}>
          <Send className="size-3.5" aria-hidden />
          {testing ? 'Testing…' : 'Send test email'}
        </Button>
      </PermissionTip>
      {meta && result && (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <ToneChip tone={meta.tone} icon={meta.icon} label={meta.label} />
          <span className="font-mono text-xs text-ink-muted">{result.durationMs} ms</span>
          {result.error && <span className="text-xs text-ink-muted">{result.error}</span>}
        </span>
      )}
    </div>
  );
}
