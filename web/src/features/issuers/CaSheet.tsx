import { useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { ErrorSchema } from '@rjsf/utils';
import { presetsQuery, saveCa } from '@/api/queries/cas';
import { metaSchemasQuery } from '@/api/queries/dns';
import { ApiError, errorMessage } from '@/api/errors';
import type { CA, CaType } from '@/api/types';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import type { SchemaFormHandle } from '@/forms/SchemaForm';
import { KIND_LABEL } from '@/lib/caKinds';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { initialDraft, toCaInput, type CaDraft } from './caBody';
import { CaKindBody, type ServerField } from './CaKindBody';

// Adaptation: the Problem schema has no structured field name, only a prose
// `detail`. This best-effort match places a 422's detail next to the field
// it names (controller ruling); anything unmatched falls back to a banner.
// acme-only — private-kind 422s are mapped by `configFieldError` below.
function fieldFromDetail(detail: string): ServerField {
  const d = detail.toLowerCase();
  if (d.includes('directory')) return 'directoryUrl';
  if (d.includes('eab') || d.includes('external account')) return 'eab';
  if (d.includes('name')) return 'name';
  return null;
}

// A private-kind 422's title is "Invalid config.<field>" or
// "Invalid config.<nested>.<field>" (internal/api's mapErr); builds the
// nested ErrorSchema SchemaForm's `extraErrors` expects, relative to
// `config` itself (SchemaForm's own schema root). Returns null when the
// title doesn't name a config field, so the caller falls back to a banner.
function configFieldError(title: string | undefined, message: string): ErrorSchema | null {
  if (!title?.startsWith('Invalid config.')) return null;
  const path = title.slice('Invalid config.'.length).split('.');
  return path.reduceRight<ErrorSchema>((acc, key) => ({ [key]: acc }) as ErrorSchema, { __errors: [message] } as unknown as ErrorSchema);
}

const KIND_OPTIONS: CaType[] = ['acme', 'localca', 'vaultpki'];

type Props = { orgId: string; open: boolean; ca?: CA; initialKind?: CaType; onOpenChange: (open: boolean) => void };

export function CaSheet({ orgId, open, ca, initialKind = 'acme', onOpenChange }: Props) {
  const qc = useQueryClient();
  const me = useMe();
  // cas:write is global-only (internal/authz/authz.go): a control the
  // caller cannot use is disabled behind PermissionTip, never hidden.
  const canWrite = can(me, 'cas:write', orgId);
  const { data: presets = [] } = useQuery(presetsQuery);
  const { data: meta } = useQuery(metaSchemasQuery);
  const signers = meta?.signers ?? [];
  const formRef = useRef<SchemaFormHandle>(null);
  const [draft, setDraft] = useState<CaDraft>(() => initialDraft(ca, initialKind));
  // Fix round 1 (#1, carried from the pre-5B CaSheet): an existing CA's name
  // was typed by someone, so an acme preset pick shouldn't clobber it.
  const [nameTouched, setNameTouched] = useState(!!ca);
  const [submitted, setSubmitted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [serverError, setServerError] = useState<{ field: ServerField; message: string } | null>(null);
  const [configError, setConfigError] = useState<ErrorSchema | undefined>(undefined);
  const [bannerError, setBannerError] = useState<string | null>(null);

  const preset = presets.find((p) => p.preset === draft.acme.preset);
  const nameOk = draft.name.trim() !== '';
  const acmeValid =
    !!draft.acme.preset &&
    nameOk &&
    (() => {
      try {
        return new URL(draft.acme.directoryUrl).protocol === 'https:';
      } catch {
        return false;
      }
    })() &&
    !(preset?.requiresEab && (!draft.acme.eabKid.trim() || !draft.acme.eabHmac));

  async function submit() {
    setSubmitted(true);
    setServerError(null);
    setConfigError(undefined);
    setBannerError(null);
    if (draft.kind === 'acme') {
      if (!acmeValid) return;
    } else {
      const formOk = formRef.current?.validate() ?? true;
      if (!nameOk || !formOk) return;
    }
    setSaving(true);
    try {
      await saveCa(qc, orgId, toCaInput(draft, { presets, ca }), ca?.id);
      onOpenChange(false);
    } catch (e) {
      // Fix round 2 (carried): a plain network failure (offline, timeout —
      // not an ApiError) must still surface, not just stop the button
      // spinning.
      if (draft.kind === 'acme') {
        const field = e instanceof ApiError ? fieldFromDetail(e.problem.detail ?? '') : null;
        setServerError({ field, message: errorMessage(e) });
      } else {
        const err = e instanceof ApiError ? configFieldError(e.problem.title, errorMessage(e)) : null;
        if (err) setConfigError(err);
        else setBannerError(errorMessage(e));
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{ca ? `Edit ${ca.name}` : 'Add certificate authority'}</SheetTitle>
          <SheetDescription className="sr-only">Certificate authority settings</SheetDescription>
        </SheetHeader>
        <form
          className="grid gap-5 px-4"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Field id="ca-type" label="Type" help="ca.type">
            <span className="inline-flex items-center gap-1.5">
              <SegmentedControl<CaType>
                id="ca-type"
                aria-label="Type"
                value={draft.kind}
                onChange={(kind) => setDraft((d) => ({ ...d, kind }))}
                options={KIND_OPTIONS.map((k) => ({
                  value: k,
                  label: KIND_LABEL[k],
                  disabled: !!ca,
                  hint: ca ? help['ca.typeLocked'].text : undefined,
                }))}
              />
              {draft.kind === 'vaultpki' && <HelpTip id="ca.vaultPki" />}
            </span>
          </Field>
          <Field id="ca-name" label="Name" error={submitted && !nameOk ? 'Required' : serverError?.field === 'name' ? serverError.message : null}>
            <Input
              id="ca-name"
              value={draft.name}
              onChange={(e) => {
                setNameTouched(true);
                setDraft((d) => ({ ...d, name: e.target.value }));
              }}
              placeholder="Let's Encrypt"
            />
          </Field>
          <CaKindBody
            draft={draft}
            setDraft={setDraft}
            ca={ca}
            presets={presets}
            signers={signers}
            submitted={submitted}
            serverError={serverError}
            extraErrors={configError}
            formRef={formRef}
            nameTouched={nameTouched}
          />
          {bannerError && (
            <p role="alert" className="text-xs">
              {bannerError}
            </p>
          )}
          <SheetFooter className="flex-row justify-end gap-2 px-0">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <PermissionTip allowed={canWrite} action="cas:write">
              <Button type="submit" disabled={!canWrite || saving}>
                Save CA
              </Button>
            </PermissionTip>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
