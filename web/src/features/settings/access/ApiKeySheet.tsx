import { useEffect, useMemo, useState } from 'react';
import { CircleAlert } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { useCreateApiKey } from '@/api/queries/apiKeys';
import type { ApiKeyCreated, ApiKeyScope } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { useMe } from '@/lib/org';
import { API_KEY_SCOPES, can, canGrantScope } from '@/lib/permissions';
import { DAY } from '@/lib/time';
import { GLOBAL } from './BindingSheet';

type Expiry = '30d' | '90d' | '1y' | 'never';
const EXPIRY_DAYS: Record<Expiry, number | null> = { '30d': 30, '90d': 90, '1y': 365, never: null };

export function ApiKeySheet({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; onCreated: (c: ApiKeyCreated) => void }) {
  const me = useMe();
  const create = useCreateApiKey();
  const scopes = useMemo(
    () => [
      ...(can(me, 'apikeys:write', null) ? [{ value: GLOBAL, label: 'All orgs' }] : []),
      ...me.orgs.filter((o) => can(me, 'apikeys:write', o.id)).map((o) => ({ value: o.id, label: o.name })),
    ],
    [me],
  );
  const initialScope = scopes.find((s) => s.value !== GLOBAL)?.value ?? scopes[0]?.value;
  const [name, setName] = useState('');
  const [scope, setScope] = useState<string | undefined>(initialScope);
  const [picked, setPicked] = useState<ApiKeyScope[]>(['certs:read']);
  const [expiry, setExpiry] = useState<Expiry>('90d');
  const [error, setError] = useState<string | null>(null);
  const orgId = scope === GLOBAL ? null : (scope ?? null);
  const grantable = (s: ApiKeyScope) => canGrantScope(me, s, orgId);

  useEffect(() => {
    if (!open) {
      setName('');
      setScope(initialScope);
      setPicked(['certs:read']);
      setExpiry('90d');
      setError(null);
    }
  }, [open, initialScope]);

  async function submit() {
    setError(null);
    const days = EXPIRY_DAYS[expiry];
    try {
      const created = await create.mutateAsync({
        name: name.trim(),
        scopes: picked.filter(grantable),
        orgId,
        expiresAt: days === null ? null : new Date(Date.now() + days * DAY).toISOString(),
      });
      // Detach the observer so the gcTime-0 mutation (and its token) leaves the cache.
      create.reset();
      onOpenChange(false);
      onCreated(created);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="grid content-start gap-6 overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>New API key</SheetTitle>
        </SheetHeader>
        <Field id="key-name" label="Name">
          <Input id="key-name" placeholder="ci-deploy" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field id="key-org" label="Scope" help="apikey.org">
          <Combobox id="key-org" aria-label="Scope" value={scope} onChange={setScope} options={scopes} placeholder="Pick an org" emptyText="No org matches." />
        </Field>
        <Field id="key-scopes" label="Permissions" help="apikey.scopes">
          <ChipSet<ApiKeyScope>
            id="key-scopes"
            aria-label="Permissions"
            value={picked}
            onChange={setPicked}
            options={API_KEY_SCOPES.map((s) => ({ value: s, label: s, disabled: !grantable(s), hint: grantable(s) ? undefined : 'Your role here does not include this.' }))}
          />
        </Field>
        <Field id="key-expiry" label="Expires" help="apikey.expiry">
          <SegmentedControl<Expiry>
            aria-label="Expires"
            value={expiry}
            onChange={setExpiry}
            options={[
              { value: '30d', label: '30 days' },
              { value: '90d', label: '90 days' },
              { value: '1y', label: '1 year' },
              { value: 'never', label: 'Never' },
            ]}
          />
        </Field>
        {error && (
          <p role="alert" className="flex items-center gap-1 text-xs">
            <CircleAlert className="size-3.5 text-failed" aria-hidden />
            {error}
          </p>
        )}
        <SheetFooter>
          <Button disabled={!name.trim() || !scope || picked.filter(grantable).length === 0 || create.isPending} onClick={() => void submit()}>
            Create
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
