import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Ban, CircleCheck, Plus, Trash2 } from 'lucide-react';
import { accountsQuery, useCreateAccount, useDeleteAccount } from '@/api/queries/accounts';
import { casQuery } from '@/api/queries/cas';
import type { AcmeAccount } from '@/api/types';
import { ApiError, errorMessage } from '@/api/errors';
import { Combobox } from '@/components/Combobox';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { CopyField } from '@/components/CopyField';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';

// Fix round 1 (#3/#4): sticky first column; see CasPage.tsx.
const stickyCol = 'sticky left-0 z-10 bg-panel';

function RegisterDialog({ orgId, open, onOpenChange }: { orgId: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { data: cas = [] } = useQuery(casQuery(orgId));
  const create = useCreateAccount(orgId);
  const [caId, setCaId] = useState<string | undefined>(cas.length === 1 ? cas[0]!.id : undefined);
  const [email, setEmail] = useState('');
  const [serverError, setServerError] = useState<{ onEmail: boolean; message: string } | null>(null);
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  async function submit() {
    setServerError(null);
    if (!caId || !emailOk) return;
    try {
      await create.mutateAsync({ caId, email });
      onOpenChange(false);
    } catch (e) {
      // Fix round 2: a plain network failure (offline, timeout — not an
      // ApiError) must still surface, not just stop the button spinning.
      const onEmail = e instanceof ApiError && (e.problem.detail ?? '').toLowerCase().includes('email');
      setServerError({ onEmail, message: errorMessage(e) });
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Register ACME account</DialogTitle>
          <DialogDescription className="sr-only">Choose a CA and a contact email</DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Field id="acct-ca" label="Certificate authority">
            <Combobox id="acct-ca" aria-label="Certificate authority" value={caId} onChange={setCaId} options={cas.map((c) => ({ value: c.id, label: c.name }))} placeholder="Choose CA" emptyText="No CAs yet" />
          </Field>
          <Field id="acct-email" label="Contact email" help="account.email" error={serverError?.onEmail ? serverError.message : null}>
            <Input id="acct-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="ops@example.com" />
          </Field>
          {serverError && !serverError.onEmail && (
            <p role="alert" className="text-xs">
              {serverError.message}
            </p>
          )}
          <DialogFooter>
            <Button type="submit" disabled={!caId || !emailOk || create.isPending}>
              {create.isPending ? 'Registering…' : 'Register'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function AccountsPage() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'accounts:write', org.id);
  const { data: accounts = [], isPending, isError, error, refetch } = useQuery(accountsQuery(org.id));
  const { data: cas = [] } = useQuery(casQuery(org.id));
  const del = useDeleteAccount(org.id);
  const [registering, setRegistering] = useState(false);
  const [deleting, setDeleting] = useState<AcmeAccount | null>(null);
  const caName = (id: string) => cas.find((c) => c.id === id)?.name ?? id;

  return (
    <section className="grid gap-4" aria-label="ACME accounts">
      {isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : isError ? (
        <ErrorState message={`Couldn't load ACME accounts. ${errorMessage(error)}`} onRetry={() => void refetch()} />
      ) : accounts.length === 0 ? (
        <EmptyState message="No ACME accounts yet.">
          <PermissionTip allowed={canWrite} action="accounts:write">
            <Button disabled={!canWrite} onClick={() => setRegistering(true)}>
              Register account
            </Button>
          </PermissionTip>
        </EmptyState>
      ) : (
        <>
          <div className="flex justify-end">
            <PermissionTip allowed={canWrite} action="accounts:write">
              <Button disabled={!canWrite} onClick={() => setRegistering(true)}>
                <Plus className="size-4" aria-hidden />
                Register account
              </Button>
            </PermissionTip>
          </div>
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={cn('w-32', stickyCol)}>CA</TableHead>
                <TableHead className="w-48">Email</TableHead>
                <TableHead className="w-24">
                  <span className="inline-flex items-center gap-1">
                    Status <HelpTip id="account.status" />
                  </span>
                </TableHead>
                <TableHead>Registration</TableHead>
                <TableHead className="w-12">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {accounts.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className={cn('truncate py-1', stickyCol)}>{caName(a.caId)}</TableCell>
                  <TableCell className="min-w-0 truncate py-1 font-mono text-xs">{a.email}</TableCell>
                  <TableCell className="py-1">
                    {a.status === 'valid' ? (
                      <ToneChip tone="valid" icon={CircleCheck} label="Valid" />
                    ) : (
                      <ToneChip tone="neutral" icon={Ban} label={a.status.charAt(0).toUpperCase() + a.status.slice(1)} />
                    )}
                  </TableCell>
                  <TableCell className="min-w-0 py-1">{a.registrationUri && <CopyField value={a.registrationUri} label="registration URI" className="min-w-0" />}</TableCell>
                  <TableCell className="py-1 text-right">
                    <PermissionTip allowed={canWrite} action="accounts:write" side="left">
                      <Button variant="ghost" size="icon-sm" className="size-7" disabled={!canWrite} aria-label={`Delete ${a.email}`} onClick={() => setDeleting(a)}>
                        <Trash2 className="size-3.5" aria-hidden />
                      </Button>
                    </PermissionTip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}
      {registering && <RegisterDialog orgId={org.id} open onOpenChange={setRegistering} />}
      <ConfirmDestructive
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete ACME account"
        consequence="Certificates that use this account stop renewing until they get another account."
        confirmText={deleting?.email ?? ''}
        actionLabel="Delete account"
        onConfirm={() => del.mutateAsync(deleting!.id)}
      />
    </section>
  );
}
