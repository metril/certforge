import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

type Props = Omit<React.ComponentProps<typeof Button>, 'aria-label' | 'asChild'> & {
  /** Accessible name and tooltip text. */
  label: string;
  /** Overrides the tooltip text (for example a permission-denial reason). */
  tip?: React.ReactNode;
};

/** Icon-only button; every one carries a tooltip. A disabled button stays one
 * stable, focusable element (aria-disabled, not native disabled) so the tooltip
 * still opens, focus survives toggling, and a guarded click neither fires nor
 * bubbles to a clickable row nor submits a form. */
export const IconButton = React.forwardRef<HTMLButtonElement, Props>(function IconButton({ label, tip, disabled, onClick, className, ...props }, ref) {
  const guarded = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (disabled) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    onClick?.(e);
  };
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          ref={ref}
          aria-label={label}
          aria-disabled={disabled || undefined}
          className={cn(disabled && 'cursor-not-allowed opacity-50 hover:bg-transparent', className)}
          onClick={guarded}
          {...props}
        />
      </TooltipTrigger>
      <TooltipContent>{tip ?? label}</TooltipContent>
    </Tooltip>
  );
});
IconButton.displayName = 'IconButton';
