import { Link } from '@tanstack/react-router';
import { ChevronDown, FolderInput, Import, Upload } from 'lucide-react';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

type Props = { orgSlug: string; canWrite: boolean };

/** Next to New certificate on the certificates list. Collapses to an
 * icon-only button below `sm`, matching TabLabel's aria-hidden-both-spans
 * pattern (the button itself carries the accessible name). */
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
  // Fix round 1 (review, Minor): `import.menu` had no HelpTip rendering it
  // anywhere, so the help.ts entry (and its `help.test.ts` coverage) was
  // dead. Sits beside the trigger, not inside it — the trigger is already a
  // dropdown button, and it and the tip need to stay independently focusable.
  if (!canWrite) {
    return (
      <div className="flex items-center gap-1">
        <PermissionTip allowed={false} action="certs:write">
          {trigger}
        </PermissionTip>
        <HelpTip id="import.menu" />
      </div>
    );
  }
  return (
    <div className="flex items-center gap-1">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem asChild>
            <Link to="/o/$org/certificates/import" params={{ org: orgSlug }} className="flex items-center gap-2">
              <FolderInput className="size-4" aria-hidden />
              From acme.sh or certbot
            </Link>
          </DropdownMenuItem>
          <DropdownMenuItem asChild>
            <Link to="/o/$org/certificates/upload" params={{ org: orgSlug }} className="flex items-center gap-2">
              <Upload className="size-4" aria-hidden />
              Upload PEM or PKCS#12
            </Link>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <HelpTip id="import.menu" />
    </div>
  );
}
