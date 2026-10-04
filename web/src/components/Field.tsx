import { cloneElement, isValidElement, type ReactNode } from 'react';
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

type Describable = { 'aria-describedby'?: string; 'aria-invalid'?: boolean };

export function Field({ id, label, help, helpText, optional, error, children, className }: Props) {
  const errorId = `${id}-error`;
  // When the child forwards aria-* to its own DOM node (the shadcn Input,
  // Textarea, ...), link the error text to it so a screen reader announces
  // it on focus, not just when the alert fires. Components with a closed
  // prop surface (SecretInput, Combobox, ...) simply ignore the extra prop.
  const content =
    error && isValidElement<Describable>(children)
      ? cloneElement(children, {
          'aria-describedby': [children.props['aria-describedby'], errorId].filter(Boolean).join(' '),
          'aria-invalid': true,
        })
      : children;
  return (
    <div className={cn('grid gap-1.5', className)}>
      <div className="flex items-center gap-1.5">
        <Label htmlFor={id}>{label}</Label>
        {optional && <span className="text-xs text-ink-muted">Optional</span>}
        {(help || helpText) && <HelpTip id={help} text={helpText} label={typeof label === 'string' ? label : undefined} />}
      </div>
      {content}
      {error && (
        <p id={errorId} role="alert" className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          {error}
        </p>
      )}
    </div>
  );
}
