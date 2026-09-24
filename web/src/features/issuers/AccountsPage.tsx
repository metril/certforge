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
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useOrg } from '@/lib/org';

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
      if (e instanceof ApiError) {
        const detail = (e.problem.detail ?? '').toLowerCase();
        setServerError({ onEmail: detail.includes('email'), message: errorMessage(e) });
      }
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
  const { data: accounts = [], isPending } = useQuery(accountsQuery(org.id));
  const { data: cas = [] } = useQuery(casQuery(org.id));
  const del = useDeleteAccount(org.id);
  const [registering, setRegistering] = useState(false);
  const [deleting, setDeleting] = useState<AcmeAccount | null>(null);
  const caName = (id: string) => cas.find((c) => c.id === id)?.name ?? id;

  return (
    <section className="grid gap-4" aria-label="ACME accounts">
      {isPending ? null : accounts.length === 0 ? (
        <EmptyState message="No ACME accounts yet.">
          <Button onClick={() => setRegistering(true)}>Register account</Button>
        </EmptyState>
      ) : (
        <>
          <div className="flex justify-end">
            <Button onClick={() => setRegistering(true)}>
              <Plus className="size-4" aria-hidden />
              Register account
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CA</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>
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
                <TableRow key={a.id} className="h-9">
                  <TableCell>{caName(a.caId)}</TableCell>
                  <TableCell className="font-mono text-xs">{a.email}</TableCell>
                  <TableCell>
                    {a.status === 'valid' ? (
                      <ToneChip tone="valid" icon={CircleCheck} label="Valid" />
                    ) : (
                      <ToneChip tone="neutral" icon={Ban} label={a.status.charAt(0).toUpperCase() + a.status.slice(1)} />
                    )}
                  </TableCell>
                  <TableCell className="max-w-72">{a.registrationUri && <CopyField value={a.registrationUri} label="registration URI" />}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" aria-label={`Delete ${a.email}`} onClick={() => setDeleting(a)}>
                      <Trash2 className="size-4" aria-hidden />
                    </Button>
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
