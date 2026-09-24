import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, ChevronDown } from 'lucide-react';
import { presetsQuery, useSaveCa } from '@/api/queries/cas';
import { UNCHANGED, type CA, type CAInput, type CAPreset } from '@/api/types';
import { ApiError, errorMessage } from '@/api/errors';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { ListInput } from '@/components/ListInput';
import { SecretInput } from '@/components/SecretInput';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';

const CUSTOM = 'custom';
type Form = {
  name: string;
  preset: CAInput['preset'] | '';
  directoryUrl: string;
  trustBundlePem: string;
  eabKid: string;
  eabHmac: string | undefined;
  resolvers: string[];
};
type ServerField = 'name' | 'directoryUrl' | 'eab' | null;

function initial(ca?: CA): Form {
  if (!ca) return { name: '', preset: '', directoryUrl: '', trustBundlePem: '', eabKid: '', eabHmac: undefined, resolvers: [] };
  return {
    name: ca.name,
    preset: ca.preset,
    directoryUrl: ca.directoryUrl,
    trustBundlePem: ca.trustBundlePem ?? '',
    eabKid: ca.eabKid ?? '',
    // Adaptation (preflight A18): the API's source of truth for "a stored EAB
    // HMAC exists" is CA.hasEab, not the presence of eabKid (a CA can have a
    // kid without ever having set an HMAC).
    eabHmac: ca.hasEab ? UNCHANGED : undefined,
    resolvers: ca.resolvers ?? [],
  };
}

const isHttps = (v: string) => {
  try {
    return new URL(v).protocol === 'https:';
  } catch {
    return false;
  }
};
const hostPort = (v: string) => (/^[\w.:[\]-]+(:\d{1,5})?$/.test(v) ? null : `${v} is not host or host:port`);

// Adaptation: the Problem schema has no structured field name, only a prose
// `detail`. This best-effort match places a 422's detail next to the field
// it names (controller ruling); anything unmatched falls back to a banner.
function fieldFromDetail(detail: string): ServerField {
  const d = detail.toLowerCase();
  if (d.includes('directory')) return 'directoryUrl';
  if (d.includes('eab') || d.includes('external account')) return 'eab';
  if (d.includes('name')) return 'name';
  return null;
}

type Props = { orgId: string; open: boolean; ca?: CA; onOpenChange: (open: boolean) => void };

export function CaSheet({ orgId, open, ca, onOpenChange }: Props) {
  const { data: presets = [] } = useQuery(presetsQuery);
  const save = useSaveCa(orgId);
  const [form, setForm] = useState<Form>(() => initial(ca));
  // Fix round 1 (#1): an existing CA's name was typed by someone, and a fresh
  // preset pick shouldn't clobber a name the operator has already edited by
  // hand — only auto-fill from the preset while the name is still whatever a
  // preset last set it to (or blank).
  const [nameTouched, setNameTouched] = useState(!!ca);
  const [submitted, setSubmitted] = useState(false);
  const [serverError, setServerError] = useState<{ field: ServerField; message: string } | null>(null);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  const preset = presets.find((p) => p.preset === form.preset);
  const custom = form.preset === CUSTOM;
  const showEab = custom || !!preset?.requiresEab;
  const errors = {
    preset: form.preset ? null : 'Choose a preset or Custom',
    name: form.name.trim() ? null : 'Required',
    directoryUrl: isHttps(form.directoryUrl) ? null : 'Use an https:// URL',
    eab: preset?.requiresEab && (!form.eabKid.trim() || !form.eabHmac) ? 'This CA requires external account binding' : null,
  };
  const valid = Object.values(errors).every((e) => !e);
  const errFor = (key: Exclude<ServerField, null>, clientErr: string | null): string | null =>
    (submitted ? clientErr : null) ??
    // Fix round 1 (#6): a 422 mapped to the EAB field while its fieldset is
    // hidden (the operator switched to a preset that doesn't show it) would
    // otherwise render nowhere; the generic banner below handles that case.
    (serverError?.field === key && (key !== 'eab' || showEab) ? serverError.message : null);

  function pickPreset(p: CAPreset) {
    // Fix round 2: re-clicking the already-selected preset card is not a
    // switch — it must not wipe EAB values (or a typed custom directory URL)
    // the operator already entered for it.
    if (p.preset === form.preset) return;
    setForm((f) => ({
      ...f,
      preset: p.preset,
      name: nameTouched ? f.name : p.name,
      directoryUrl: p.directoryUrl,
      // Fix round 1 (#1): a previous preset's EAB kid/HMAC must not survive a
      // switch — otherwise a preset that doesn't need EAB (or an edited CA)
      // posts a stale secret, or __unchanged__ for one that was never re-entered.
      eabKid: '',
      eabHmac: undefined,
    }));
  }

  async function submit() {
    setSubmitted(true);
    setServerError(null);
    if (!valid || !form.preset) return;
    const kid = form.eabKid.trim();
    // Fix round 1 (#1): only send EAB fields at all when the EAB fieldset is
    // actually shown (`showEab`: the preset requires it, or it's custom).
    // Otherwise a hidden EAB section (e.g. after switching off a preset that
    // used it) sends nothing rather than a stale value; clearing the kid on
    // an EAB'd CA of a still-shown preset still sends `eabHmac: ''` to remove
    // the stored HMAC (preflight A18).
    const body: CAInput = {
      name: form.name.trim(),
      preset: form.preset,
      directoryUrl: form.directoryUrl.trim(),
      trustBundlePem: custom && form.trustBundlePem.trim() ? form.trustBundlePem.trim() : undefined,
      eabKid: showEab && kid ? kid : undefined,
      eabHmac: showEab ? (kid ? form.eabHmac : ca?.hasEab ? '' : undefined) : undefined,
      resolvers: form.resolvers,
    };
    try {
      await save.mutateAsync({ id: ca?.id, body });
      onOpenChange(false);
    } catch (e) {
      // Fix round 2: a plain network failure (offline, timeout — not an
      // ApiError) must still surface, not just stop the button spinning.
      const field = e instanceof ApiError ? fieldFromDetail(e.problem.detail ?? '') : null;
      setServerError({ field, message: errorMessage(e) });
    }
  }

  const card = (key: string, title: string, sub: string, eab: boolean, onPick: () => void) => {
    const on = form.preset === key;
    return (
      <button
        key={key}
        type="button"
        aria-pressed={on}
        onClick={onPick}
        className={cn('grid gap-0.5 rounded-md border p-3 text-left', on ? 'border-primary bg-primary/8' : 'border-border hover:bg-subtle')}
      >
        <span className="flex items-center gap-1.5 text-sm font-semibold">
          {on && <Check className="size-3.5 text-primary" aria-hidden />}
          {title}
          {eab && <span className="rounded-sm bg-subtle px-1 text-xs font-normal">EAB</span>}
        </span>
        <span className="truncate font-mono text-xs text-ink-muted">{sub}</span>
      </button>
    );
  };

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
          <fieldset className="grid gap-2">
            <legend className="mb-2 flex items-center gap-1.5 text-sm font-semibold">
              Preset <HelpTip id="ca.preset" />
            </legend>
            <div className="grid grid-cols-2 gap-2">
              {presets.map((p) =>
                // Adaptation (preflight A20): `custom` is one of the 7 presets
                // the API returns (directoryUrl: ''), not a card this component
                // adds itself — a second Custom card would duplicate it, and
                // `new URL('').host` throws and crashes the sheet.
                card(p.preset, p.name, p.preset === CUSTOM ? 'Any ACME directory' : new URL(p.directoryUrl).host, p.requiresEab, () => pickPreset(p)),
              )}
            </div>
            {submitted && errors.preset && <p className="text-xs">{errors.preset}</p>}
          </fieldset>
          {form.preset && (
            <>
              <Field id="ca-name" label="Name" error={errFor('name', errors.name)}>
                <Input
                  id="ca-name"
                  value={form.name}
                  onChange={(e) => {
                    setNameTouched(true);
                    set('name', e.target.value);
                  }}
                  placeholder="Let's Encrypt"
                />
              </Field>
              <Field id="ca-dir" label="Directory URL" help="ca.directoryUrl" error={errFor('directoryUrl', errors.directoryUrl)}>
                <Input
                  id="ca-dir"
                  className="font-mono text-xs"
                  value={form.directoryUrl}
                  onChange={(e) => set('directoryUrl', e.target.value)}
                  placeholder="https://ca.example.com/acme/directory"
                />
              </Field>
              {custom && (
                <Field id="ca-trust" label="Trust bundle" help="ca.trustBundle" optional>
                  <Textarea
                    id="ca-trust"
                    rows={5}
                    className="font-mono text-xs"
                    value={form.trustBundlePem}
                    onChange={(e) => set('trustBundlePem', e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                </Field>
              )}
              {showEab && (
                <fieldset className="grid gap-3">
                  <legend className="mb-1 flex items-center gap-1.5 text-sm font-semibold">
                    External account binding <HelpTip id="ca.eab" />
                  </legend>
                  <Field id="ca-eab-kid" label="Key ID" optional={custom}>
                    <Input id="ca-eab-kid" className="font-mono text-xs" value={form.eabKid} onChange={(e) => set('eabKid', e.target.value)} placeholder="kid_3xAmPlE" />
                  </Field>
                  <Field id="ca-eab-hmac" label="HMAC key" optional={custom} error={errFor('eab', errors.eab)}>
                    <SecretInput id="ca-eab-hmac" label="HMAC key" stored={!!ca?.hasEab} value={form.eabHmac} onChange={(v) => set('eabHmac', v)} />
                  </Field>
                </fieldset>
              )}
              <Collapsible>
                <CollapsibleTrigger className="flex items-center gap-1 text-sm font-semibold">
                  <ChevronDown className="size-4" aria-hidden />
                  Advanced
                </CollapsibleTrigger>
                <CollapsibleContent className="pt-3">
                  <Field id="ca-resolvers" label="Resolvers" help="ca.resolvers" optional>
                    <ListInput id="ca-resolvers" value={form.resolvers} onChange={(v) => set('resolvers', v)} placeholder="1.1.1.1:53" validate={hostPort} />
                  </Field>
                </CollapsibleContent>
              </Collapsible>
            </>
          )}
          {serverError && (!serverError.field || (serverError.field === 'eab' && !showEab)) && (
            <p role="alert" className="text-xs">
              {serverError.message}
            </p>
          )}
          <SheetFooter className="px-0">
            <Button type="submit" disabled={save.isPending}>
              Save CA
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
