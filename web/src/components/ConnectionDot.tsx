import { forwardRef, type ComponentPropsWithoutRef } from 'react';
import type { Client } from '@/api/types';
import { CONNECTION_META, connection } from '@/lib/clientStatus';
import { cn } from '@/lib/utils';

type Props = { client: Pick<Client, 'status' | 'online' | 'lastSeen'>; label?: string } & Omit<ComponentPropsWithoutRef<'span'>, 'children'>;

/** Dot plus word (never colour alone). `label` overrides the word, for the
 * detail header's "Offline since <time>". forwardRef so it can sit inside
 * a `Tooltip`/`PermissionTip`'s `asChild` trigger (Radix clones and needs
 * to attach a ref to the actual DOM node), matching Sidebar's TargetLink. */
export const ConnectionDot = forwardRef<HTMLSpanElement, Props>(function ConnectionDot({ client, label, className, ...rest }, ref) {
  const m = CONNECTION_META[connection(client)];
  return (
    <span ref={ref} className={cn('inline-flex min-w-0 items-center gap-1.5 whitespace-nowrap text-sm', className)} {...rest}>
      <span aria-hidden className={cn('size-2 shrink-0 rounded-full', m.dot)} />
      <span className="truncate">{label ?? m.label}</span>
    </span>
  );
});
