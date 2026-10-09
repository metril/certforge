import type { ReactNode } from 'react';
import { PermissionTip } from '@/components/PermissionTip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

type Side = 'top' | 'right' | 'bottom' | 'left';

/** Tooltip for a grant write control the caller has already disabled: the
 * permission when the role lacks clients:write, "The client is revoked" when
 * it has it but the client is revoked, nothing otherwise. */
export function ClientWriteTip({ canWrite, revoked, side, children }: { canWrite: boolean; revoked: boolean; side?: Side; children: ReactNode }) {
  if (!canWrite) {
    return (
      <PermissionTip allowed={false} action="clients:write" side={side}>
        {children}
      </PermissionTip>
    );
  }
  if (!revoked) return <>{children}</>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent side={side}>The client is revoked</TooltipContent>
    </Tooltip>
  );
}

/** Denial reason for a disabled grant write control, or undefined when allowed. */
export function clientWriteReason(canWrite: boolean, revoked: boolean): string | undefined {
  if (!canWrite) return 'Needs the clients:write permission';
  return revoked ? 'The client is revoked' : undefined;
}
