import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { downloadVersion, versionsQuery, type PemPart } from '@/api/queries/certificates';
import type { Certificate } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { LATER } from '@/lib/nav';
import { fmtDate } from '@/lib/time';

type Format = 'pem' | 'der' | 'p12' | 'jks';
type Props = { orgId: string; cert: Certificate; initialVersionId?: string; canExportKey: boolean; onOpenChange: (open: boolean) => void };

export function DownloadSheet({ orgId, cert, initialVersionId, canExportKey, onOpenChange }: Props) {
  const { data: versions = [] } = useQuery(versionsQuery(orgId, cert.id));
  const [versionId, setVersionId] = useState(initialVersionId ?? cert.currentVersion?.id);
  const [format, setFormat] = useState<Format>('pem');
  const [parts, setParts] = useState<PemPart[]>(['fullchain']);
  const [busy, setBusy] = useState(false);

  async function download() {
    if (!versionId || parts.length === 0) return;
    setBusy(true);
    try {
      await downloadVersion(orgId, cert.id, versionId, { format: 'pem', parts }, cert.name);
      onOpenChange(false);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Download</SheetTitle>
          <SheetDescription className="sr-only">Choose version, format, and parts</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          <Field id="dl-version" label="Version">
            <Combobox
              id="dl-version"
              mono
              value={versionId}
              onChange={setVersionId}
              options={versions.map((v) => ({
                value: v.id,
                label: `${v.serial}${v.id === cert.currentVersion?.id ? ' (current)' : ''}`,
                hint: `expires ${fmtDate(v.notAfter)}`,
              }))}
              placeholder="Choose version"
              emptyText="No versions"
            />
          </Field>
          <Field id="dl-format" label="Format" help="download.format">
            <SegmentedControl<Format>
              id="dl-format"
              aria-label="Format"
              value={format}
              onChange={setFormat}
              options={[
                { value: 'pem', label: 'PEM' },
                { value: 'der', label: 'DER', disabled: true, hint: LATER },
                { value: 'p12', label: 'PKCS#12', disabled: true, hint: LATER },
                { value: 'jks', label: 'JKS', disabled: true, hint: LATER },
              ]}
            />
          </Field>
          <Field id="dl-parts" label="Parts" help="download.parts">
            <div className="flex flex-wrap items-center gap-2">
              <ChipSet<PemPart>
                id="dl-parts"
                aria-label="Parts"
                value={parts}
                onChange={setParts}
                options={[
                  { value: 'cert', label: 'cert' },
                  { value: 'chain', label: 'chain' },
                  { value: 'fullchain', label: 'fullchain' },
                  { value: 'key', label: 'key', disabled: !canExportKey, hint: canExportKey ? undefined : 'Needs the keys:export permission' },
                  { value: 'combined', label: 'combined', disabled: !canExportKey, hint: canExportKey ? undefined : 'Needs the keys:export permission' },
                ]}
              />
              <HelpTip id="download.key" />
            </div>
          </Field>
          <Button disabled={!versionId || parts.length === 0 || busy} onClick={() => void download()}>
            {parts.length > 1 ? 'Download ZIP' : 'Download PEM'}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}
