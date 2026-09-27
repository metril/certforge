import { Link } from '@tanstack/react-router';
import { ChevronDown, FolderInput, Import, Upload } from 'lucide-react';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

type Props = { orgSlug: string; canWrite: boolean };

/** Next to New certificate on the certificates list. Collapses to an
 * icon-only button below `sm`, matching TabLabel's aria-hidden-both-spans
 * pattern (the button itself carries the accessible name). The "From
 * acme.sh or certbot" item is a plain anchor, not a typed `Link`: Task 6
 * adds the `/import` route this points at, which doesn't exist yet. */
export function ImportMenu({ orgSlug, canWrite }: Props) {
  const trigger = (
    <Button variant="outline" aria-label="Import" disabled={!canWrite}>
      <Import className="size-4" aria-hidden />
      <span aria-hidden className="hidden sm:inline">
        Import
      </span>
      <ChevronDown aria-hidden className="hidden size-4 sm:inline" />
    </Button>
  );
  if (!canWrite) {
    return (
      <PermissionTip allowed={false} action="certs:write">
        {trigger}
      </PermissionTip>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem asChild>
          <a href={`/o/${orgSlug}/certificates/import`} className="flex items-center gap-2">
            <FolderInput className="size-4" aria-hidden />
            From acme.sh or certbot
          </a>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link to="/o/$org/certificates/upload" params={{ org: orgSlug }} className="flex items-center gap-2">
            <Upload className="size-4" aria-hidden />
            Upload PEM or PKCS#12
          </Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
