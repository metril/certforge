import { CalendarClock } from 'lucide-react';
import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { EXPIRING_DAYS, type Tone } from '@/lib/status';
import { DAY, fmtDate, relDays } from '@/lib/time';

/** Deviations ("monitor ValidityBar"): Monitor has no `notBefore`, so this
 * stands in for ValidityBar/StatusChip on the not-after row of a monitor's
 * Last check block — validityTone's own expiry rule (EXPIRING_DAYS), the
 * relative days as the visible label, and the exact date on hover. */
function expiryTone(notAfter: string, now: number): Tone {
  const end = Date.parse(notAfter);
  if (end <= now) return 'expired';
  if (end - now < EXPIRING_DAYS * DAY) return 'expiring';
  return 'valid';
}

export function ExpiryChip({ notAfter, now = Date.now() }: { notAfter: string; now?: number }) {
  const tone = expiryTone(notAfter, now);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <ToneChip tabIndex={0} tone={tone} icon={CalendarClock} label={relDays(notAfter, now)} />
      </TooltipTrigger>
      <TooltipContent side="top">{fmtDate(notAfter)}</TooltipContent>
    </Tooltip>
  );
}
