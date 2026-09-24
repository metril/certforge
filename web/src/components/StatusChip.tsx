import type { LucideIcon } from 'lucide-react';
import type { CertStatus } from '@/api/types';
import type { HelpKey } from '@/lib/help';
import { STATUS_META, type Tone } from '@/lib/status';
import { cn } from '@/lib/utils';
import { HelpTip } from './HelpTip';

/** Alpha used by each tinted chip's `bg-<tone>/NN` class, kept in one place so
 * the contrast test (StatusChip.test.tsx) proves the actual rendered tint. */
export const CHIP_TINT: Record<'valid' | 'expiring' | 'drift', number> = {
  valid: 0.12,
  expiring: 0.15,
  drift: 0.12,
};

const CHIP: Record<Tone, string> = {
  valid: 'border-valid/40 bg-valid/12',
  expiring: 'border-expiring/60 bg-expiring/15',
  expired: 'border-expired bg-expired',
  failed: 'border-failed bg-transparent',
  pending: 'cf-dash',
  drift: 'border-drift/50 bg-drift/12',
  neutral: 'border-border bg-subtle',
};
// Controller ruling: chip words use the `ink` token in both themes (the
// pre-flight found `expiring` text directly in its tone colour fails AA on
// white). `expired` is the one filled/saturated chip, so it needs the
// contrasting `on-status` token instead (proven in styles/tokens.test.ts).
const TEXT: Record<Tone, string> = {
  valid: 'text-ink',
  expiring: 'text-ink',
  expired: 'text-on-status',
  failed: 'text-ink',
  pending: 'text-ink',
  drift: 'text-ink',
  neutral: 'text-ink',
};
const ICON: Record<Tone, string> = {
  valid: 'text-valid',
  expiring: 'text-expiring',
  expired: 'text-on-status',
  failed: 'text-failed',
  pending: 'text-pending',
  drift: 'text-drift',
  neutral: 'text-ink-muted',
};

export function ToneChip({
  tone,
  icon: Icon,
  label,
  help,
  className,
}: {
  tone: Tone;
  icon: LucideIcon;
  label: string;
  help?: HelpKey;
  className?: string;
}) {
  return (
    <span className={cn('inline-flex h-6 items-center gap-1 whitespace-nowrap rounded-sm border px-2 text-xs font-semibold', CHIP[tone], TEXT[tone], className)}>
      <Icon className={cn('size-3.5', ICON[tone])} aria-hidden />
      {label}
      {help && <HelpTip id={help} />}
    </span>
  );
}

/** failed is outlined (an event, not a persistent state); expired is filled;
 * pending uses the animated dash border (see .cf-dash in app.css). */
export function StatusChip({ status, withHelp = false }: { status: CertStatus; withHelp?: boolean }) {
  const m = STATUS_META[status];
  return <ToneChip tone={m.tone} icon={m.icon} label={m.label} help={withHelp ? m.help : undefined} />;
}
