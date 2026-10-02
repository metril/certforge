import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import { apiKeysQuery } from '@/api/queries/apiKeys';
import { useRefreshMe } from '@/api/queries/auth';
import { useCreateBinding } from '@/api/queries/bindings';
import { usersQuery } from '@/api/queries/users';
import type { Role, SubjectType } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle, useSheetGuard } from '@/components/ui/sheet';
import { GLOBAL, keyState, scopeLabel } from '@/lib/apiKeys';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can, canAnywhere } from '@/lib/permissions';

export const ROLE_LABEL: Record<Role, string> = {
  admin: 'Admin', 'org-admin': 'Org admin', operator: 'Operator', viewer: 'Viewer', auditor: 'Auditor',
};
const ROLES: Role[] = ['viewer', 'auditor', 'operator', 'org-admin', 'admin'];

type Props = { open: boolean; onOpenChange: (open: boolean) => void; fixedType?: SubjectType };

export function BindingSheet({ open, onOpenChange, fixedType }: Props) {
  const guard = useSheetGuard(onOpenChange);
  const me = useMe();
  const create = useCreateBinding();
  const refreshMe = useRefreshMe();

  // Server rules mirrored here (2A Task 10 / controller ruling): a user
  // subject needs bindings:write somewhere; an oidc_group subject always
  // needs GLOBAL bindings:write (group mappings are admin-only, whatever
  // org the binding targets); an apikey subject needs apikeys:write
  // somewhere (the exact org is fixed once a key is picked, to that key's
  // own scope).
  const canUser = canAnywhere(me, 'bindings:write');
  const canGroup = can(me, 'bindings:write', null);
  const canApiKey = canAnywhere(me, 'apikeys:write');
  const defaultType: SubjectType = canUser ? 'user' : canGroup ? 'oidc_group' : 'apikey';

  const scopes = useMemo(
    () => [
      ...(can(me, 'bindings:write', null) ? [{ value: GLOBAL, label: 'All orgs' }] : []),
      ...me.orgs.filter((o) => can(me, 'bindings:write', o.id)).map((o) => ({ value: o.id, label: o.name })),
    ],
    [me],
  );
  const initialScope = scopes.find((s) => s.value !== GLOBAL)?.value ?? scopes[0]?.value;
  const [type, setType] = useState<SubjectType>(fixedType ?? defaultType);
  const [subject, setSubject] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [scope, setScope] = useState<string | undefined>(type === 'apikey' ? undefined : initialScope);
  const [error, setError] = useState<string | null>(null);
  const dirty = subject !== '' || role !== 'viewer' || type !== (fixedType ?? defaultType);
  const users = useQuery({ ...usersQuery, enabled: open && type === 'user' });
  const keys = useQuery({ ...apiKeysQuery(), enabled: open && type === 'apikey' });
  // Only keys the caller may actually bind (apikeys:write at the key's own
  // scope), excluding revoked and expired ones (controller ruling, fix
  // round 1).
  const bindableKeys = useMemo(
    () => (keys.data ?? []).filter((k) => keyState(k) === 'active' && can(me, 'apikeys:write', k.orgId)),
    [keys.data, me],
  );

  useEffect(() => {
    if (!open) {
      const t = fixedType ?? defaultType;
      setType(t);
      setSubject('');
      setRole('viewer');
      setScope(t === 'apikey' ? undefined : initialScope);
      setError(null);
    }
  }, [open, fixedType, defaultType, initialScope]);

  async function save() {
    setError(null);
    try {
      const trimmed = subject.trim();
      await create.mutateAsync({ subjectType: type, subject: trimmed, role, orgId: scope === GLOBAL ? null : scope });
      // M5: a binding that grants the caller's own account a new role
      // changes what `can`/`canAnywhere` allow right away — refetch /auth/me
      // and re-run route guards so gating updates immediately, not just on
      // the query's own next background refetch.
      if (type === 'user' && trimmed === me.user.id) await refreshMe();
      guard.close();
    } catch (e) {
      setError(e instanceof ApiError && e.status === 409 ? 'This binding already exists.' : errorMessage(e));
    }
  }

  return (
    <Sheet guard={guard} open={open} form dirty={open && dirty} onOpenChange={onOpenChange}>
      <SheetContent className="grid content-start gap-6 overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{fixedType === 'oidc_group' ? 'Add group mapping' : 'Add binding'}</SheetTitle>
        </SheetHeader>
        {!fixedType && (
          <Field id="binding-type" label="Subject" help="binding.subjectType">
            <SegmentedControl<SubjectType>
              aria-label="Subject type"
              value={type}
              onChange={(v) => {
                setType(v);
                setSubject('');
                setScope(v === 'apikey' ? undefined : initialScope);
              }}
              options={[
                { value: 'user', label: 'User', disabled: !canUser, hint: canUser ? undefined : help['binding.userDisabled'].text },
                { value: 'oidc_group', label: 'Group', disabled: !canGroup, hint: canGroup ? undefined : help['binding.groupDisabled'].text },
                { value: 'apikey', label: 'API key', disabled: !canApiKey, hint: canApiKey ? undefined : help['binding.apikeyDisabled'].text },
              ]}
            />
          </Field>
        )}
        {type === 'user' && (
          <Field id="binding-user" label="User">
            <Combobox
              id="binding-user"
              aria-label="User"
              value={subject || undefined}
              onChange={(v) => setSubject(v ?? '')}
              options={(users.data ?? []).map((u) => ({ value: u.id, label: u.displayName, hint: u.email ?? undefined, keywords: [u.email ?? ''] }))}
              placeholder="Pick a user"
              emptyText="No user matches."
            />
          </Field>
        )}
        {type === 'oidc_group' && (
          <Field id="binding-group" label="Group" help="binding.group">
            <Input id="binding-group" className="font-mono" placeholder="platform-admins" value={subject} onChange={(e) => setSubject(e.target.value)} />
          </Field>
        )}
        {type === 'apikey' && (
          <Field id="binding-apikey" label="API key" help="binding.apikey">
            <Combobox
              id="binding-apikey"
              aria-label="API key"
              mono
              value={subject || undefined}
              onChange={(v) => {
                setSubject(v ?? '');
                const key = bindableKeys.find((k) => k.id === v);
                setScope(key ? (key.orgId ?? GLOBAL) : undefined);
              }}
              options={bindableKeys.map((k) => ({ value: k.id, label: k.name, hint: k.prefix, keywords: [k.prefix] }))}
              placeholder="Pick a key"
              emptyText="No API key matches."
            />
          </Field>
        )}
        <Field id="binding-role" label="Role" help="binding.role">
          <SegmentedControl<Role> aria-label="Role" value={role} onChange={setRole} options={ROLES.map((r) => ({ value: r, label: ROLE_LABEL[r] }))} />
        </Field>
        <Field id="binding-scope" label="Scope" help="binding.scope">
          <Combobox
            id="binding-scope"
            aria-label="Scope"
            value={scope}
            onChange={setScope}
            options={type === 'apikey' ? (scope ? [{ value: scope, label: scopeLabel(me, scope === GLOBAL ? null : scope) }] : []) : scopes}
            placeholder={type === 'apikey' ? 'Pick a key first' : 'Pick an org'}
            emptyText="No org matches."
            disabled={type === 'apikey'}
          />
        </Field>
        {error && (
          <p role="alert" className="flex items-center gap-1 text-xs">
            <CircleAlert className="size-3.5 text-failed" aria-hidden />
            {error}
          </p>
        )}
        <SheetFooter>
          <Button disabled={!subject.trim() || !scope || create.isPending} onClick={() => void save()}>
            Save
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
