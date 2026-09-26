import type { Client } from '@/api/types';
import { CONNECTION_META, connection } from '@/lib/clientStatus';
import { cn } from '@/lib/utils';

/** Dot plus word (never colour alone). `label` overrides the word, for the
 * detail header's "Offline since <time>". */
export function ConnectionDot({ client, label }: { client: Pick<Client, 'status' | 'online' | 'lastSeen'>; label?: string }) {
  const m = CONNECTION_META[connection(client)];
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 whitespace-nowrap text-sm">
      <span aria-hidden className={cn('size-2 shrink-0 rounded-full', m.dot)} />
      <span className="truncate">{label ?? m.label}</span>
    </span>
  );
}
