import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { errorMessage } from '@/api/errors';
import { attemptsQuery, certificateQuery, useRenewCertificates } from '@/api/queries/certificates';
import type { Certificate } from '@/api/types';
import { ManualDnsCard } from '@/features/certificates/ManualDnsCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { livePoll } from '@/lib/polling';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { renewToastHandlers } from '@/lib/renewToast';
import { AttemptsTab } from './AttemptsTab';
import { CertificateHeader } from './CertificateHeader';
import { DeploymentsTab } from './DeploymentsTab';
import { DownloadSheet } from './DownloadSheet';
import { OverviewTab } from './OverviewTab';
import { SettingsTab } from './SettingsTab';
import { TABS, type Tab } from './tabs';
import { UploadVersionSheet } from './UploadVersionSheet';
import { VersionsTab } from './VersionsTab';

const LABEL: Record<Tab, string> = { overview: 'Overview', versions: 'Versions', attempts: 'Attempts', deployments: 'Deployments', settings: 'Settings' };

const LIVE_WINDOW_MS = 60_000;

export function CertificateDetail({ id, tab }: { id: string; tab: Tab }) {
  const org = useOrg();
  const me = useMe();
  const navigate = useNavigate();
  const renew = useRenewCertificates(org.id);
  // I1 (Important): a renew/create just queued from this page (the header's
  // Renew now, either tab's empty-state Renew, or the wizard landing here
  // with a fresh issuance) has no `running` attempt yet for up to a couple
  // of seconds — the worker hasn't picked the job up — so `running` alone
  // misses that window and the new attempt wouldn't appear for up to 30s
  // (the list-pace interval). `liveUntil` covers it: initialised already-hot
  // when the wizard hands off here with something in flight (its `tab`
  // param is only ever 'attempts' when it just queued an issuance), and
  // reset by every renew handler on this page.
  const [liveUntil, setLiveUntil] = useState<number | null>(() => (tab === 'attempts' ? Date.now() + LIVE_WINDOW_MS : null));
  const markLive = () => setLiveUntil(Date.now() + LIVE_WINDOW_MS);
  // Polling (ruling): the certificate itself only needs to refresh quickly
  // while an attempt is actually running (a new current version can land at
  // any moment); attemptsQuery already tracks that at its own 2s/30s pace, so
  // this reuses its cached data instead of re-deriving it from cert.status.
  const { data: attempts } = useQuery(attemptsQuery(org.id, id));
  const running = !!attempts?.some((a) => a.outcome === 'running');
  const { data: cert, isPending, error } = useQuery({
    ...certificateQuery(org.id, id),
    refetchInterval: (query) => {
      const status = (query.state.data as Certificate | undefined)?.status;
      const live = running || status === 'pending' || (liveUntil !== null && Date.now() < liveUntil);
      return livePoll(live);
    },
  });
  const [download, setDownload] = useState<{ open: boolean; versionId?: string }>({ open: false });
  const [uploadVersionOpen, setUploadVersionOpen] = useState(false);

  if (isPending) return <p className="text-ink-muted">Loading…</p>;
  if (error) return <p role="alert">{errorMessage(error)}</p>;

  const goTab = (t: Tab) => void navigate({ to: '/o/$org/certificates/$id/$tab', params: { org: org.slug, id, tab: t } });
  // I1 + I2: shared by both tabs' empty-state Renew button — same 60s live
  // window as the header's, and the same failure toast (renew.mutate's own
  // hook is `meta: { silent: true }`; without this, a renew failure here
  // had no toast and no error surfaced anywhere on the page).
  const renewNow = () => {
    markLive();
    renew.mutate([cert.id], renewToastHandlers(cert.name));
  };

  return (
    <div className="grid gap-6">
      <nav aria-label="Breadcrumb" className="text-sm">
        <Link to="/o/$org/certificates" params={{ org: org.slug }} className="text-ink-muted hover:text-ink">
          Certificates
        </Link>
      </nav>
      <CertificateHeader
        cert={cert}
        orgId={org.id}
        orgSlug={org.slug}
        canRenew={can(me, 'certs:issue', org.id)}
        canDelete={can(me, 'certs:write', org.id)}
        canWrite={can(me, 'certs:write', org.id)}
        onDownload={() => setDownload({ open: true })}
        onRenewed={() => {
          markLive();
          goTab('attempts');
        }}
        onUploadVersion={() => setUploadVersionOpen(true)}
      />
      {/* Always mounted (controller ruling): it fetches its own manual-dns
          records and renders nothing when none are waiting, so there's no
          separate "is this a pending manual-dns cert" check to keep in sync
          with the attempt/rule state. */}
      <ManualDnsCard orgId={org.id} cert={cert} canConfirm={can(me, 'certs:issue', org.id)} />
      {/* Fix wave (Important): this grid's single-column track (line ~76) is
          otherwise sized by Tabs' own `min-width: auto` default — a grid
          item's automatic minimum size is its content's, and TabsList's
          five `whitespace-nowrap` triggers refuse to shrink below their
          combined min-content width (403 px), overflowing a 375 px
          viewport regardless of TabsList's own overflow-x-auto. `min-w-0`
          lets the item (and TabsList's scrollbar) shrink to the track. */}
      <Tabs value={tab} onValueChange={(v) => goTab(v as Tab)} className="min-w-0">
        <TabsList className="max-w-full overflow-x-auto">
          {TABS.map((t) => (
            <TabsTrigger key={t} value={t}>
              {LABEL[t]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="overview">
          <OverviewTab cert={cert} orgId={org.id} />
        </TabsContent>
        <TabsContent value="versions">
          <VersionsTab
            cert={cert}
            orgId={org.id}
            onDownload={(versionId) => setDownload({ open: true, versionId })}
            onRenew={renewNow}
          />
        </TabsContent>
        <TabsContent value="attempts" className="pt-4">
          <AttemptsTab orgId={org.id} certId={cert.id} caId={cert.effective?.caId?.value} onRenew={renewNow} />
        </TabsContent>
        <TabsContent value="deployments" className="pt-4">
          <DeploymentsTab cert={cert} orgId={org.id} orgSlug={org.slug} />
        </TabsContent>
        <TabsContent value="settings">
          <SettingsTab cert={cert} orgId={org.id} orgSlug={org.slug} />
        </TabsContent>
      </Tabs>
      {download.open && (
        <DownloadSheet
          orgId={org.id}
          cert={cert}
          initialVersionId={download.versionId}
          canExportKey={can(me, 'keys:export', org.id)}
          onOpenChange={(o) => !o && setDownload({ open: false })}
        />
      )}
      {uploadVersionOpen && <UploadVersionSheet orgId={org.id} id={cert.id} onOpenChange={setUploadVersionOpen} />}
    </div>
  );
}
