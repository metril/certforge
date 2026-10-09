import { Card, CardBody, CardHeader } from '@/components/Card';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Plus, Trash2 } from 'lucide-react';
import { bindingsQuery, useDeleteBinding } from '@/api/queries/bindings';
import type { RoleBinding } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { scopeLabel } from '@/lib/apiKeys';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can, canAnywhere } from '@/lib/permissions';
import { BindingSheet, ROLE_LABEL } from './access/BindingSheet';
import { IconButton } from '@/components/IconButton';

// D1 ruling: group mappings are oidc_group role bindings, reusing Task 4's
// binding sheet/mutations with fixedType so this stays the single source of
// truth for the role-binding write path. Visible to any bindings:read
// holder; only a global bindings:write holder can add or remove one (server
// rule: group mappings are admin-only regardless of the target org).
export function GroupMappings() {
  const me = useMe();
  const canWrite = can(me, 'bindings:write', null);
  const q = useQuery({ ...bindingsQuery({ subjectType: 'oidc_group' }), enabled: canAnywhere(me, 'bindings:read') });
  const del = useDeleteBinding();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<RoleBinding | null>(null);
  if (!canAnywhere(me, 'bindings:read')) return null;
  return (
    <Card role="region" aria-labelledby="group-mappings">
      <CardHeader
        titleId="group-mappings"
        title={
          <span className="flex items-center gap-1.5">
            Group mappings <HelpTip id="auth.groupMappings" />
          </span>
        }
      />
      <CardBody className="grid gap-2">
      <ul className="grid">
        {(q.data ?? []).map((b) => (
          <li key={b.id} className="flex h-9 items-center gap-3 border-b border-border text-sm">
            <span className="font-mono text-xs">{b.subject}</span>
            <span className="text-ink-muted">→</span>
            <span>{ROLE_LABEL[b.role]}</span>
            <span className="text-ink-muted">{scopeLabel(me, b.orgId)}</span>
            {canWrite && (
              <IconButton variant="ghost" size="icon" className="ml-auto" label={`Remove ${b.subject} ${b.role}`} onClick={() => setRemoving(b)}>
                <Trash2 className="size-4" aria-hidden />
              </IconButton>
            )}
          </li>
        ))}
      </ul>
      {canWrite ? (
        <Button variant="outline" className="w-fit" onClick={() => setAdding(true)}>
          <Plus className="size-4" aria-hidden />
          Add mapping
        </Button>
      ) : (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>
              <Button variant="outline" className="w-fit" disabled>
                <Plus className="size-4" aria-hidden />
                Add mapping
              </Button>
            </span>
          </TooltipTrigger>
          <TooltipContent side="right">{help['binding.groupDisabled'].text}</TooltipContent>
        </Tooltip>
      )}
      </CardBody>
      <BindingSheet open={adding} onOpenChange={setAdding} fixedType="oidc_group" />
      <ConfirmDestructive
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={`Remove mapping for ${removing?.subject ?? ''}`}
        consequence="Members of this group lose the role on their next request."
        confirmText={removing?.subject ?? ''}
        actionLabel="Remove"
        onConfirm={() => del.mutateAsync(removing!.id)}
      />
    </Card>
  );
}
