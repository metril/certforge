import { useState, type MutableRefObject, type ReactNode } from 'react';
import { Link, type LinkProps } from '@tanstack/react-router';
import { ChevronLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardBody } from '@/components/Card';
import { NavGuard, type NavLoc } from '@/components/NavGuard';
import { PageHeader } from '@/components/PageHeader';
import type { HelpKey } from '@/lib/help';

export type FormPageProps = {
  title: string;
  help?: HelpKey;
  /** Breadcrumb link back to the list or detail page. */
  backTo: { label: string; link: LinkProps };
  /** Right-aligned header buttons (Cancel / Save). */
  actions: ReactNode;
  /** Sticky summary column beside the form (wrapped in a Card). */
  rail?: ReactNode;
  /** Blocks leaving the page (router navigation and tab close) behind a "Discard changes?" dialog. */
  dirty: boolean;
  /** Set `.current = true` right before the post-save navigation so it is not blocked. */
  bypass: MutableRefObject<boolean>;
  children: ReactNode;
};

// Moving to another page is blocked; a search-only change on this page is not.
const staysOnPage = (cur: NavLoc, next: NavLoc) => cur.routeId === next.routeId && JSON.stringify(cur.params) === JSON.stringify(next.params);

/** Full-page editor: breadcrumb, header actions, form body and an optional sticky summary rail. */
export function FormPage({ title, help, backTo, actions, rail, dirty, bypass, children }: FormPageProps) {
  const [confirming, setConfirming] = useState(false);
  return (
    <>
      <Link {...backTo.link} className="mb-2 inline-flex items-center gap-1 text-sm text-ink-muted hover:text-ink">
        <ChevronLeft className="size-4" aria-hidden />
        {backTo.label}
      </Link>
      <PageHeader title={title} help={help} actions={actions} />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_var(--rail-width)]">
        <div className="grid min-w-0 gap-4">{children}</div>
        {rail && (
          <aside aria-label="Summary" className="min-w-0 lg:sticky lg:top-6 lg:self-start">
            <Card>
              <CardBody>{rail}</CardBody>
            </Card>
          </aside>
        )}
      </div>
      <NavGuard keepsOpen={staysOnPage} active={dirty} confirming={confirming} setConfirming={setConfirming} bypass={bypass} onDiscard={() => setConfirming(false)} />
    </>
  );
}

/** Cancel + Save pair for `FormPage.actions`. */
export function FormActions({ onCancel, save }: { onCancel: () => void; save: ReactNode }) {
  return (
    <>
      <Button variant="outline" onClick={onCancel}>
        Cancel
      </Button>
      {save}
    </>
  );
}
