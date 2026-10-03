import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import type { HelpKey } from '@/lib/help';
import { HelpTip } from './HelpTip';

type Props = {
  id: string;
  label: string;
  help?: HelpKey;
  helpText?: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  onText?: string;
  offText?: string;
  disabled?: boolean;
};

// role="switch" carries aria-checked, so screen readers already announce the
// state change on toggle; the state text below is a sighted-user affordance
// and stays aria-hidden to avoid double-announcing.
export function SwitchField({ id, label, help, helpText, checked, onCheckedChange, onText = 'On', offText = 'Off', disabled }: Props) {
  return (
    <div className="flex min-h-9 items-center gap-3">
      <div className="flex min-w-0 flex-1 items-center gap-1.5">
        <Label htmlFor={id}>{label}</Label>
        {(help || helpText) && <HelpTip id={help} text={helpText} label={typeof label === 'string' ? label : undefined} />}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} disabled={disabled} />
      <span className="w-40 text-sm text-ink-muted" aria-hidden>
        {checked ? onText : offText}
      </span>
    </div>
  );
}
