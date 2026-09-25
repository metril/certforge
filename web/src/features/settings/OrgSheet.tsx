import { useEffect, useState } from 'react';
import { CircleAlert } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { useSaveOrg } from '@/api/queries/orgs';
import type { Org } from '@/api/types';
import { Field } from '@/components/Field';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { SLUG_RE, toSlug } from '@/features/setup/slug';

export function OrgSheet({ org, onClose, onSaved }: { org: Org | 'new' | null; onClose: () => void; onSaved: () => Promise<void> }) {
  const save = useSaveOrg();
  const editing = org !== null && org !== 'new' ? org : null;
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [slugTouched, setSlugTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName(editing?.name ?? '');
    setSlug(editing?.slug ?? '');
    setSlugTouched(false);
    setError(null);
  }, [org, editing?.name, editing?.slug]);

  const slugError = editing || !slug ? null : slug === 'all' ? '"all" is reserved.' : SLUG_RE.test(slug) ? null : 'Use lowercase letters, digits and hyphens.';

  async function submit() {
    setError(null);
    try {
      await save.mutateAsync({ id: editing?.id, body: { slug, name: name.trim() } });
      await onSaved();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <Sheet open={org !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="grid content-start gap-6 sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{editing ? `Rename ${editing.name}` : 'New organization'}</SheetTitle>
        </SheetHeader>
        <Field id="org-name" label="Name">
          <Input
            id="org-name"
            placeholder="Home lab"
            value={name}
            maxLength={100}
            onChange={(e) => {
              setName(e.target.value);
              if (!editing && !slugTouched) setSlug(toSlug(e.target.value));
            }}
          />
        </Field>
        <Field id="org-slug" label="Slug" help={editing ? 'org.slugPermanent' : 'setup.orgSlug'} error={slugError}>
          <Input
            id="org-slug"
            className="font-mono"
            placeholder="home-lab"
            value={slug}
            readOnly={!!editing}
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(e.target.value);
            }}
          />
        </Field>
        {error && (
          <p role="alert" className="flex items-center gap-1 text-xs">
            <CircleAlert className="size-3.5 text-failed" aria-hidden />
            {error}
          </p>
        )}
        <SheetFooter>
          <Button disabled={!name.trim() || !slug || !!slugError || save.isPending} onClick={() => void submit()}>
            {editing ? 'Save' : 'Create'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
