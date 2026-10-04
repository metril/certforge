import { useNavigate, useSearch } from '@tanstack/react-router';
import type { CertBrief } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { can, canAnywhere } from '@/lib/permissions';
import { useAllOrgs, useMe, useOrg, useOrgSlugOf } from '@/lib/org';
import { DAY, relDays } from '@/lib/time';
import { ExpiryHorizon } from '../ExpiryHorizon';
import { RecentActivity } from '../RecentActivity';
import { CertRow } from './CertRow';

/** Block 3: one card with two tabs, Expiry horizon and Recent activity. The
 * activity tab is omitted for callers without audit:read. */
export function InsightsCard({ certs, beyond, now }: { certs: CertBrief[]; beyond: number; now: number }) {
  const org = useOrg();
  const allOrgs = useAllOrgs();
  const slugOf = useOrgSlugOf();
  const me = useMe();
  const search = useSearch({ from: '/_app/o/$org/overview' });
  const navigate = useNavigate({ from: '/o/$org/overview' });
  const range = search.range ?? null;
  const setRange = (r: [number, number] | null) => void navigate({ search: (prev) => ({ ...prev, range: r ?? undefined }), replace: true });
  const slug = (c: CertBrief) => (allOrgs ? slugOf(c.orgId) : org.slug);
  const showActivity = allOrgs ? canAnywhere(me, 'audit:read') : can(me, 'audit:read', org.id);
  const inRange = range
    ? certs.filter((c) => {
        if (!c.notAfter || c.status === 'revoked') return false;
        const d = (Date.parse(c.notAfter) - now) / DAY;
        // Review fix: a range starting at 0 ("from now") also catches an
        // already-expired certificate (d < 0), not just d === 0 exactly.
        return (range[0] === 0 ? d <= range[1] : d >= range[0]) && d <= range[1];
      })
    : [];
  return (
    <Tabs defaultValue="horizon" className="gap-3 rounded-lg border border-border bg-panel p-4">
      <TabsList>
        <TabsTrigger value="horizon">Expiry horizon</TabsTrigger>
        {showActivity && <TabsTrigger value="activity">Recent activity</TabsTrigger>}
      </TabsList>
      <TabsContent value="horizon" className="grid content-start gap-6">
        <ExpiryHorizon certs={certs} beyond={beyond} now={now} range={range} onRange={setRange} />
        {range && (
          <section aria-label="Expiring in range" className="grid gap-2">
            <div className="flex items-center gap-3">
              <h2 className="text-base font-semibold">
                Expiring in {range[0]} to {range[1]} days
              </h2>
              <Button variant="link" size="sm" onClick={() => setRange(null)}>
                Clear range
              </Button>
            </div>
            <ul className="grid">
              {inRange.map((c) => (
                <CertRow key={c.id} cert={c} org={slug(c)} right={relDays(c.notAfter!, now)} />
              ))}
            </ul>
          </section>
        )}
      </TabsContent>
      {showActivity && (
        <TabsContent value="activity">
          <RecentActivity orgId={allOrgs ? undefined : org.id} />
        </TabsContent>
      )}
    </Tabs>
  );
}
