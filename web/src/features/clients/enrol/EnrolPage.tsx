import { useEffect, useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { ApiError, errorMessage } from '@/api/errors';
import { useCreateClient, useReenrollClient } from '@/api/queries/clients';
import { sitesQuery } from '@/api/queries/sites';
import type { ClientCreated } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { PageHeader } from '@/components/PageHeader';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { TokenPanel } from './TokenPanel';
import { WaitingPanel } from './WaitingPanel';

export function EnrolPage() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'clients:write', org.id);
  const create = useCreateClient(org.id);
  const reenroll = useReenrollClient(org.id);
  const { data: sites = [] } = useQuery(sitesQuery(org.id));
  const [name, setName] = useState('');
  const [siteId, setSiteId] = useState<string | undefined>();
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [created, setCreated] = useState<ClientCreated | null>(null);

  // Leaving the page drops the one-time token from the mutation cache.
  const { reset: resetCreate } = create;
  const { reset: resetReenroll } = reenroll;
  useEffect(
    () => () => {
      resetCreate();
      resetReenroll();
    },
    [resetCreate, resetReenroll],
  );

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!name.trim()) {
      setNameError('Enter a name.');
      return;
    }
    try {
      setCreated(await create.mutateAsync({ name: name.trim(), siteId: siteId ?? null }));
    } catch (err) {
      if (err instanceof ApiError && (err.status === 409 || err.status === 422)) setNameError(errorMessage(err));
      else setFormError(errorMessage(err));
    }
  };

  const newToken = async () => {
    if (!created) return;
    try {
      setCreated(await reenroll.mutateAsync(created.client.id));
    } catch (err) {
      setFormError(errorMessage(err));
    }
  };

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm">
        <Link to="/o/$org/clients" params={{ org: org.slug }} className="text-ink-muted hover:text-ink">
          Clients
        </Link>
      </nav>
      <PageHeader title="Enrol client" />
      {created ? (
        <div className="grid max-w-[720px] gap-6">
          <TokenPanel created={created} />
          <WaitingPanel
            orgId={org.id}
            orgSlug={org.slug}
            clientId={created.client.id}
            expiresAt={created.expiresAt}
            renewing={reenroll.isPending}
            onNewToken={() => void newToken()}
          />
          {formError && (
            <p role="alert" className="text-sm">
              {formError}
            </p>
          )}
        </div>
      ) : (
        <form noValidate onSubmit={(e) => void submit(e)} className="grid max-w-[560px] gap-4">
          <Field id="client-name" label="Name" help="client.name" error={nameError}>
            <Input
              id="client-name"
              value={name}
              placeholder="web-1"
              autoComplete="off"
              disabled={!canWrite}
              onChange={(e) => {
                setName(e.target.value);
                setNameError(null);
              }}
            />
          </Field>
          <Field id="client-site" label="Site" help="client.site" optional>
            <Combobox
              id="client-site"
              aria-label="Site"
              value={siteId}
              onChange={setSiteId}
              options={sites.map((s) => ({ value: s.id, label: s.name }))}
              placeholder="No site"
              emptyText="No sites in this org."
              disabled={!canWrite}
            />
          </Field>
          {formError && (
            <p role="alert" className="text-sm">
              {formError}
            </p>
          )}
          <div>
            <PermissionTip allowed={canWrite} action="clients:write">
              <Button type="submit" disabled={!canWrite || create.isPending}>
                Create token
              </Button>
            </PermissionTip>
          </div>
        </form>
      )}
    </>
  );
}
