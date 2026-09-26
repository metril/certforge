import { useState } from 'react';
import type { ClientCreated } from '@/api/types';
import { CopyField } from '@/components/CopyField';
import { HelpTip } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SnippetBlock } from '@/components/SnippetBlock';
import { fmtDateTime } from '@/lib/time';
import { composeSnippet, dockerRunSnippet } from './snippets';

type Kind = 'run' | 'compose';

/** The one-time token and ready-to-paste snippets. Rendered by the Enrol
 * page; it never stores the token anywhere. */
export function TokenPanel({ created }: { created: ClientCreated }) {
  const [kind, setKind] = useState<Kind>('run');
  return (
    <section aria-label="Enrolment token" className="grid min-w-0 gap-4">
      <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-sm sm:grid-cols-[120px_minmax(0,1fr)] sm:items-center">
        <dt className="flex items-center gap-1.5 text-ink-muted">
          Token <HelpTip id="client.token" />
        </dt>
        <dd className="min-w-0">
          <CopyField value={created.token} label="enrolment token" className="w-full" />
        </dd>
        <dt className="text-ink-muted">Agent URL</dt>
        <dd className="min-w-0 truncate font-mono text-xs">{created.agentUrl}</dd>
        <dt className="text-ink-muted">Expires</dt>
        <dd>
          <time dateTime={created.expiresAt}>{fmtDateTime(created.expiresAt)}</time>
        </dd>
      </dl>
      <div className="grid min-w-0 gap-2">
        <div className="flex items-center gap-1.5">
          <SegmentedControl<Kind>
            aria-label="Run with"
            size="sm"
            value={kind}
            onChange={setKind}
            options={[
              { value: 'run', label: 'docker run' },
              { value: 'compose', label: 'Compose' },
            ]}
          />
          <HelpTip id="client.snippet" />
        </div>
        <SnippetBlock
          label={kind === 'run' ? 'docker run command' : 'Compose file'}
          value={kind === 'run' ? dockerRunSnippet(created.token) : composeSnippet(created.token)}
        />
      </div>
    </section>
  );
}
