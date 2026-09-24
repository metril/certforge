import { useQuery } from '@tanstack/react-query';
import { orgsQuery } from '@/api/queries/orgs';
import { errorMessage } from '@/api/errors';
import { HelpTip } from '@/components/HelpTip';

/** Read-only orgs list for Settings → General (docs/design.md "Settings":
 * "General (base URL, orgs, sites)"). Adaptation: no /sites endpoint exists
 * in Phase 1A, so only orgs are listed (see api/queries/orgs.ts). */
export function OrgsList() {
  const q = useQuery(orgsQuery);
  return (
    <section aria-labelledby="orgs-title" className="mt-8 max-w-[720px]">
      <h3 id="orgs-title" className="mb-2 flex items-center gap-1.5 text-sm font-semibold">
        Organizations
        <HelpTip id="settings.orgs" />
      </h3>
      {q.isPending && <p className="text-sm text-ink-muted">Loading…</p>}
      {q.isError && (
        <p role="alert" className="text-xs">
          {errorMessage(q.error)}
        </p>
      )}
      {q.data && (
        <ul className="grid gap-1">
          {q.data.map((org) => (
            <li key={org.id} className="flex items-center gap-2 border-b border-border py-2 text-sm">
              <span>{org.name}</span>
              <span className="font-mono text-xs text-ink-muted">{org.slug}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
