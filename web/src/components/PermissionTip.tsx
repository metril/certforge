import type { ReactNode } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

/** Wraps an already-disabled control with a tooltip naming the permission it
 * needs (generalizes CertificateHeader's Renew/Delete pattern to every other
 * gated write control). Pass the control disabled based on `allowed` itself;
 * this only adds the tooltip, and only when `allowed` is false. */
export function PermissionTip({
  allowed,
  action,
  side,
  children,
}: {
  allowed: boolean;
  action: string;
  side?: 'top' | 'right' | 'bottom' | 'left';
  children: ReactNode;
}) {
  if (allowed) return <>{children}</>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent side={side}>Needs the {action} permission</TooltipContent>
    </Tooltip>
  );
}
