import { Eye, Pencil, Send, Trash2 } from 'lucide-react';
import { plural } from '@/api/queries/certificates';
import { IconButton } from '@/components/IconButton';

type Props = {
  name: string;
  grantCount: number;
  canWrite: boolean;
  onOpen: () => void;
  onDelete: () => void;
  /** Task 8: a server-run deploy target's own grants live on its detail sheet, not a client's. */
  onGrants?: () => void;
};

/** Edit (or View, read-only), an optional Grants action (server-run deploy
 * targets), and Delete; Delete is blocked while grants use the item. */
export function RowActions({ name, grantCount, canWrite, onOpen, onDelete, onGrants }: Props) {
  const blocked = grantCount > 0;
  const delTip = !canWrite ? 'Needs the delivery:write permission' : blocked ? `Used by ${plural(grantCount, 'grant')}. Remove those grants first.` : undefined;
  const del = (
    <IconButton tip={delTip} variant="ghost" size="icon-sm" className="size-7" disabled={!canWrite || blocked} label={`Delete ${name}`} onClick={onDelete}>
      <Trash2 className="size-3.5" aria-hidden />
    </IconButton>
  );
  return (
    <span className="inline-flex justify-end">
      <IconButton variant="ghost" size="icon-sm" className="size-7" label={canWrite ? `Edit ${name}` : `View ${name}`} onClick={onOpen}>
        {canWrite ? <Pencil className="size-3.5" aria-hidden /> : <Eye className="size-3.5" aria-hidden />}
      </IconButton>
      {onGrants && (
        <IconButton variant="ghost" size="icon-sm" className="size-7" label={`Grants ${name}`} onClick={onGrants}>
          <Send className="size-3.5" aria-hidden />
        </IconButton>
      )}
      {del}
    </span>
  );
}

export function UsedBy({ count }: { count: number }) {
  return count > 0 ? <span className="whitespace-nowrap">{plural(count, 'grant')}</span> : <span className="text-ink-muted">–</span>;
}
