import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { CircleCheck, CircleX, Clock, Send } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { testChannel } from '@/api/queries/channels';
import type { Channel, DeliveryResult } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { help } from '@/lib/help';

// DeliveryResult.status is typed as the full DeliveryStatus enum, though an
// inline test never actually returns "pending" (schema.d.ts's own comment)
// — a pending entry keeps this exhaustive without ever being rendered.
const RESULT_META = {
  pending: { label: 'Pending', tone: 'pending' as const, icon: Clock },
  delivered: { label: 'Delivered', tone: 'valid' as const, icon: CircleCheck },
  failed: { label: 'Failed', tone: 'failed' as const, icon: CircleX },
};

type Props = {
  /** The saved channel to test; undefined on a not-yet-created channel. */
  channel?: Channel;
  /** The channels list's own query key org (the route org, not necessarily
   * channel.orgId for another org's allOrgs channel) — invalidated after a
   * test so the channel's last delivery moves. */
  orgId: string;
  /** True while the draft differs from the saved channel: Send test always
   * uses the saved config (Review Focus, "Tests against unsaved drafts"). */
  dirty: boolean;
  canWrite: boolean;
};

/**
 * Sends a test event to the saved channel now (Task 3) and shows the
 * result locally — never cached, cleared on any draft change (dirty) or on
 * unmount, per "UI conventions for this plan" → Test results.
 */
export function ChannelTest({ channel, orgId, dirty, canWrite }: Props) {
  const qc = useQueryClient();
  const [result, setResult] = useState<DeliveryResult | null>(null);
  const [testing, setTesting] = useState(false);
  const disabled = !channel || dirty || testing;
  const reason = !canWrite ? undefined : !channel ? undefined : dirty ? help['channel.testSaved'].text : undefined;

  async function run() {
    if (!channel) return;
    setTesting(true);
    try {
      const r = await testChannel(channel);
      setResult(r);
      void qc.invalidateQueries({ queryKey: ['channels', orgId] });
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setTesting(false);
    }
  }

  // Clear a stale result once the draft diverges or the saved config changes (not just hide it while dirty).
  const configKey = JSON.stringify([channel?.config, channel?.events, channel?.minSeverity, channel?.storedSecrets]);
  const [seen, setSeen] = useState({ dirty, configKey });
  if (seen.dirty !== dirty || seen.configKey !== configKey) {
    setSeen({ dirty, configKey });
    if (result) setResult(null);
  }

  const shown = !dirty && result;
  const meta = shown ? RESULT_META[shown.status] : undefined;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <PermissionTip allowed={canWrite && !dirty} action="alerts:write" reason={reason}>
        <Button type="button" variant="outline" size="sm" disabled={disabled || !canWrite} onClick={() => void run()}>
          <Send className="size-3.5" aria-hidden />
          {testing ? 'Testing…' : 'Send test'}
        </Button>
      </PermissionTip>
      <HelpTip id="channel.test" />
      {shown && meta && (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <ToneChip tone={meta.tone} icon={meta.icon} label={meta.label} />
          <span className="font-mono text-xs text-ink-muted">{shown.durationMs} ms</span>
          {shown.error && <span className="text-xs text-ink-muted">{shown.error}</span>}
        </span>
      )}
    </div>
  );
}
