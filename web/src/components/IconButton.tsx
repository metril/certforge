import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

type Props = Omit<React.ComponentProps<typeof Button>, 'aria-label' | 'asChild'> & {
  /** Accessible name and tooltip text. */
  label: string;
  /** Overrides the tooltip text (for example a permission-denial reason). */
  tip?: React.ReactNode;
};

/** Icon-only button; every one carries a tooltip. A disabled button receives no
 * pointer events, so it is wrapped in a focusable span that hosts the tooltip. */
export const IconButton = React.forwardRef<HTMLButtonElement, Props>(function IconButton({ label, tip, disabled, ...props }, ref) {
  const button = <Button ref={ref} aria-label={label} disabled={disabled} {...props} />;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{disabled ? <span tabIndex={0} className="inline-flex">{button}</span> : button}</TooltipTrigger>
      <TooltipContent>{tip ?? label}</TooltipContent>
    </Tooltip>
  );
});
IconButton.displayName = 'IconButton';
