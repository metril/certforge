import { useQuery } from '@tanstack/react-query';
import { CircleOff } from 'lucide-react';
import { settingsQuery } from '@/api/queries/settings';
import { CopyField } from '@/components/CopyField';
import { HelpTip } from '@/components/HelpTip';
import { SnippetBlock } from '@/components/SnippetBlock';
import { ToneChip } from '@/components/StatusChip';

function scrapeUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, '')}/metrics`;
}

function scrapeConfig(scrapeUrlValue: string): string {
  const u = new URL(scrapeUrlValue);
  return [
    'scrape_configs:',
    '  - job_name: certforge',
    `    scheme: ${u.protocol.replace(':', '')}`,
    '    static_configs:',
    `      - targets: ['${u.host}']`,
    '    authorization:',
    '      type: Bearer',
    '      credentials_file: /etc/prometheus/certforge.token',
  ].join('\n');
}

/**
 * The Prometheus section's own "Scrape URL" row (Task 6 brief), the
 * SchemaSection `actions` render-prop below the enabled switch and bearer
 * token field. Never renders the token itself — the YAML snippet points
 * Prometheus at a `credentials_file` instead, so nothing here (URL, mono
 * text, copy) ever carries the secret value.
 */
export function PrometheusScrape({ value }: { value: Record<string, unknown> }) {
  const general = useQuery(settingsQuery('general'));
  const baseUrl = (general.data?.value?.baseUrl as string | undefined) || window.location.origin;
  const enabled = value.enabled === true;
  const url = scrapeUrl(baseUrl);

  return (
    <div className="grid gap-2">
      <div className="flex items-center gap-1.5">
        <span className="text-sm font-medium">Scrape URL</span>
        <HelpTip id="prometheus.scrape" />
      </div>
      {enabled ? (
        <>
          <CopyField value={url} label="scrape URL" />
          <SnippetBlock label="Prometheus scrape config" value={scrapeConfig(url)} />
        </>
      ) : (
        <ToneChip tone="neutral" icon={CircleOff} label="Off" />
      )}
    </div>
  );
}
