import { Eye, Pencil, Trash2 } from 'lucide-react';
import { plural } from '@/api/queries/certificates';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

/** Edit (or View, read-only) and Delete; Delete is blocked while grants use the item. */
export function RowActions({ name, grantCount, canWrite, onOpen, onDelete }: { name: string; grantCount: number; canWrite: boolean; onOpen: () => void; onDelete: () => void }) {
  const blocked = grantCount > 0;
  const del = (
    <Button variant="ghost" size="icon-sm" className="size-7" disabled={!canWrite || blocked} aria-label={`Delete ${name}`} onClick={onDelete}>
      <Trash2 className="size-3.5" aria-hidden />
    </Button>
  );
  return (
    <span className="inline-flex justify-end">
      <Button variant="ghost" size="icon-sm" className="size-7" aria-label={canWrite ? `Edit ${name}` : `View ${name}`} onClick={onOpen}>
        {canWrite ? <Pencil className="size-3.5" aria-hidden /> : <Eye className="size-3.5" aria-hidden />}
      </Button>
      {!canWrite ? (
        <PermissionTip allowed={false} action="delivery:write" side="left">
          {del}
        </PermissionTip>
      ) : blocked ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0} className="inline-flex">
              {del}
            </span>
          </TooltipTrigger>
          <TooltipContent side="left">{`Used by ${plural(grantCount, 'grant')}. Remove those grants first.`}</TooltipContent>
        </Tooltip>
      ) : (
        del
      )}
    </span>
  );
}

export function UsedBy({ count }: { count: number }) {
  return count > 0 ? <span className="whitespace-nowrap">{plural(count, 'grant')}</span> : <span className="text-ink-muted">–</span>;
}
