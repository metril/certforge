import { Card } from '@/components/Card';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import type { ImportResult } from '@/api/types';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { casQuery } from '@/api/queries/cas';
import { useImportCertificates } from '@/api/queries/imports';
import { Combobox } from '@/components/Combobox';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { Field } from '@/components/Field';
import { PageHeader } from '@/components/PageHeader';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { MAX_ARCHIVE_BYTES } from '@/lib/files';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { Dropzone } from './Dropzone';
import { ImportPreview } from './ImportPreview';

function summaryLine(items: ImportResult['items']): string {
  const create = items.filter((i) => i.action === 'create').length;
  const skip = items.length - create;
  return `${create} to create · ${skip} skipped`;
}

/** `/o/$org/certificates/import` (Task 6): an archive dry-run preview, then
 * import for real. A dry run and the real run that follows return the same
 * `ImportItem[]` by design (server contract, task-6-brief), so this page
 * renders the same `ImportPreview` table for both, only swapping which
 * button is enabled and, once real, letting `certificateId` rows link out. */
export function ImportPage() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'certs:write', org.id);
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const cas = useQuery(casQuery(org.id));
  const importMutation = useImportCertificates(org.id);

  const [archive, setArchive] = useState<File | null>(null);
  const [caId, setCaId] = useState<string | undefined>(undefined);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [caError, setCaError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  // Certificates created before a real import failed; they stay stored.
  const [partial, setPartial] = useState<ImportResult['items']>([]);
  const [lastDryRun, setLastDryRun] = useState(true);
  const [previewing, setPreviewing] = useState(false);
  const [importing, setImporting] = useState(false);

  const tooLarge = !!archive && archive.size > MAX_ARCHIVE_BYTES;
  const effectiveArchiveError = archiveError ?? (tooLarge ? 'Larger than 32 MiB.' : undefined);
  const ready = !!archive && !!caId && !tooLarge;
  const createCount = result ? result.items.filter((i) => i.action === 'create').length : 0;
  const alreadyImported = result?.dryRun === false;

  function onArchiveChange(f: File | null) {
    setArchive(f);
    setResult(null);
    setArchiveError(null);
    setFormError(null);
  }
  function onCaChange(v: string | undefined) {
    setCaId(v);
    setResult(null);
    setCaError(null);
    setFormError(null);
  }

  async function run(dryRun: boolean) {
    if (!archive || !caId || tooLarge) return;
    setLastDryRun(dryRun);
    setArchiveError(null);
    setCaError(null);
    setFormError(null);
    setPartial([]);
    if (dryRun) setPreviewing(true);
    else setImporting(true);
    try {
      const res = await importMutation.mutateAsync({ archive, caId, dryRun });
      setResult(res);
      if (!dryRun) {
        const created = res.items.filter((i) => i.action === 'create').length;
        toast.success(`Imported ${created} certificate${created === 1 ? '' : 's'}`);
      }
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.status === 413) {
          setArchiveError('Larger than 32 MiB.');
          return;
        }
        if (e.status === 422) {
          const field = fieldOfTitle(e.problem.title);
          const detail = e.problem.detail ?? e.message;
          if (field === 'caId' || /ACME account/i.test(detail)) {
            setCaError(detail);
            return;
          }
          setArchiveError(detail);
          return;
        }
        if (e.status === 400 || e.status === 415) {
          setArchiveError(e.problem.detail ?? e.message);
          return;
        }
      }
      if (e instanceof ApiError && Array.isArray(e.problem.imported)) setPartial(e.problem.imported as ImportResult['items']);
      setFormError(errorMessage(e));
    } finally {
      if (dryRun) setPreviewing(false);
      else setImporting(false);
    }
  }

  return (
    <div className="grid gap-6">
      <nav aria-label="Breadcrumb" className="text-sm">
        <Link to="/o/$org/certificates" params={{ org: org.slug }} className="text-ink-muted hover:text-ink">
          Certificates
        </Link>
      </nav>
      <PageHeader title="Import certificates" />
      <Card className="grid max-w-[720px] gap-5 p-4">
        <Field id="import-archive" label="Archive" help="import.archive" error={effectiveArchiveError}>
          <Dropzone
            id="import-archive"
            accept=".zip,.tar.gz,.tgz"
            maxBytes={MAX_ARCHIVE_BYTES}
            value={archive}
            onChange={onArchiveChange}
            error={effectiveArchiveError}
            disabled={!canWrite}
          />
        </Field>
        <Field id="import-ca" label="CA" help="import.ca" error={caError}>
          <Combobox
            id="import-ca"
            aria-label="CA"
            value={caId}
            onChange={onCaChange}
            options={(cas.data ?? []).map((c) => ({ value: c.id, label: c.name, hint: c.preset }))}
            placeholder="Choose a CA"
            emptyText="No CAs yet."
            disabled={!canWrite}
          />
        </Field>
        <div>
          <PermissionTip allowed={canWrite} action="certs:write">
            <Button disabled={!canWrite || !ready || previewing || importing} onClick={() => void run(true)}>
              {previewing ? 'Previewing…' : 'Preview'}
            </Button>
          </PermissionTip>
        </div>
      </Card>
      {formError ? (
        <div className="grid gap-4">
          <ErrorState message={formError} onRetry={() => void run(lastDryRun)} />
          {partial.length > 0 && (
            <section aria-label="Imported before the failure" className="grid gap-4">
              <p className="text-sm text-ink-muted">
                Import failed after creating {partial.length} certificate{partial.length === 1 ? '' : 's'}. They are stored; Retry skips them.
              </p>
              <ImportPreview items={partial} orgSlug={org.slug} isMdUp={isMdUp} />
            </section>
          )}
        </div>
      ) : result && result.items.length === 0 ? (
        <EmptyState message="No acme.sh or certbot certificates in this archive.">
          <Button variant="outline" onClick={() => onArchiveChange(null)}>
            Choose another file
          </Button>
        </EmptyState>
      ) : (
        result && (
          <section aria-label="Import preview" className="grid gap-4">
            <p className="text-sm text-ink-muted">{summaryLine(result.items)}</p>
            <ImportPreview items={result.items} orgSlug={org.slug} isMdUp={isMdUp} />
            <div>
              <PermissionTip allowed={canWrite} action="certs:write">
                <Button disabled={!canWrite || createCount === 0 || previewing || importing || alreadyImported} onClick={() => void run(false)}>
                  {importing ? 'Importing…' : `Import ${createCount} certificate${createCount === 1 ? '' : 's'}`}
                </Button>
              </PermissionTip>
            </div>
          </section>
        )
      )}
    </div>
  );
}
