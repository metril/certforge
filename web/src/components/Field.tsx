import type { ReactNode } from 'react';
import { CircleAlert } from 'lucide-react';
import { Label } from '@/components/ui/label';
import type { HelpKey } from '@/lib/help';
import { cn } from '@/lib/utils';
import { HelpTip } from './HelpTip';

type Props = {
  id: string;
  label: string;
  help?: HelpKey;
  helpText?: string;
  optional?: boolean;
  error?: string | null;
  children: ReactNode;
  className?: string;
};

export function Field({ id, label, help, helpText, optional, error, children, className }: Props) {
  return (
    <div className={cn('grid gap-1.5', className)}>
      <div className="flex items-center gap-1.5">
        <Label htmlFor={id}>{label}</Label>
        {optional && <span className="text-xs text-ink-muted">Optional</span>}
        {(help || helpText) && <HelpTip id={help} text={helpText} />}
      </div>
      {children}
      {error && (
        <p id={`${id}-error`} className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          {error}
        </p>
      )}
    </div>
  );
}
