import { useState, type ReactNode } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Ban, RefreshCw, Trash2 } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { useDeleteClient, useReenrollClient, useRevokeClient, useUpdateClient } from '@/api/queries/clients';
import type { Client, ClientCreated, Site } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { HelpKey } from '@/lib/help';
import { TokenDialog } from './TokenDialog';

function ActionRow({ label, help, children }: { label: string; help: HelpKey; children: ReactNode }) {
  return (
    <div className="flex min-h-9 flex-wrap items-center justify-between gap-3">
      <span className="flex items-center gap-1.5 text-sm font-semibold">
        {label}
        <HelpTip id={help} />
      </span>
      {children}
    </div>
  );
}

type Props = { client: Client; orgId: string; orgSlug: string; sites: Site[]; canWrite: boolean };
type Confirm = 'reenroll' | 'revoke' | 'delete' | null;

export function SettingsTab({ client, orgId, orgSlug, sites, canWrite }: Props) {
  const navigate = useNavigate();
  const update = useUpdateClient(orgId, client.id);
  const revoke = useRevokeClient(orgId);
  const reenroll = useReenrollClient(orgId);
  const del = useDeleteClient(orgId);
  const [name, setName] = useState(client.name);
  const [siteId, setSiteId] = useState<string | undefined>(client.siteId ?? undefined);
  const [nameError, setNameError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [token, setToken] = useState<ClientCreated | null>(null);
  const dirty = name.trim() !== client.name || (siteId ?? null) !== client.siteId;
  const deletable = client.status === 'revoked' || client.status === 'pending';

  const save = async () => {
    if (!name.trim()) {
      setNameError('Enter a name.');
      return;
    }
    try {
      await update.mutateAsync({ name: name.trim(), siteId: siteId ?? null });
      setNameError(null);
    } catch (e) {
      setNameError(errorMessage(e));
    }
  };
  const discard = () => {
    setName(client.name);
    setSiteId(client.siteId ?? undefined);
    setNameError(null);
  };

  return (
    <div className="grid max-w-[720px] gap-8">
      <section aria-label="Client details" className="grid gap-4">
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
        <div className="flex flex-wrap gap-2">
          <PermissionTip allowed={canWrite} action="clients:write">
            <Button disabled={!canWrite || !dirty || update.isPending} onClick={() => void save()}>
              Save
            </Button>
          </PermissionTip>
          {dirty && (
            <Button variant="ghost" onClick={discard}>
              Discard changes
            </Button>
          )}
        </div>
      </section>
      <section aria-label="Identity" className="grid gap-2 border-t border-border pt-6">
        {client.status !== 'revoked' && (
          <ActionRow label="Re-enrol" help="client.reenroll">
            <PermissionTip allowed={canWrite} action="clients:write" side="left">
              <Button variant="outline" disabled={!canWrite} onClick={() => setConfirm('reenroll')}>
                <RefreshCw className="size-4" aria-hidden />
                Re-enrol
              </Button>
            </PermissionTip>
          </ActionRow>
        )}
        {client.status !== 'revoked' && (
          <ActionRow label="Revoke" help="client.revoke">
            <PermissionTip allowed={canWrite} action="clients:write" side="left">
              <Button variant="outline" disabled={!canWrite} onClick={() => setConfirm('revoke')}>
                <Ban className="size-4" aria-hidden />
                Revoke
              </Button>
            </PermissionTip>
          </ActionRow>
        )}
        <ActionRow label="Delete" help="client.delete">
          <PermissionTip allowed={canWrite} action="clients:write" side="left">
            <Button variant="outline" disabled={!canWrite || !deletable} onClick={() => setConfirm('delete')}>
              <Trash2 className="size-4" aria-hidden />
              Delete
            </Button>
          </PermissionTip>
        </ActionRow>
      </section>
      <ConfirmDestructive
        open={confirm === 'reenroll'}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Re-enrol ${client.name}`}
        consequence="The agent is disconnected and its certificate refused until it enrols with the new token."
        confirmText={client.name}
        actionLabel="Re-enrol"
        onConfirm={async () => setToken(await reenroll.mutateAsync(client.id))}
      />
      <ConfirmDestructive
        open={confirm === 'revoke'}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Revoke ${client.name}`}
        consequence="The agent is disconnected and refused from now on; files already on the host stay."
        confirmText={client.name}
        actionLabel="Revoke"
        onConfirm={() => revoke.mutateAsync(client.id)}
      />
      <ConfirmDestructive
        open={confirm === 'delete'}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Delete ${client.name}`}
        consequence="The client, its grants and its hook history are deleted."
        confirmText={client.name}
        actionLabel="Delete"
        onConfirm={async () => {
          await del.mutateAsync(client.id);
          void navigate({ to: '/o/$org/clients', params: { org: orgSlug } });
        }}
      />
      <TokenDialog
        created={token}
        onDone={() => {
          setToken(null);
          reenroll.reset();
        }}
      />
    </div>
  );
}
