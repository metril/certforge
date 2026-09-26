// Kept in its own tiny module, separate from CertificateDetail.tsx: the
// route's `beforeLoad` (eagerly bundled, since it must run before the lazy
// route component even loads) needs `TABS` to validate the `:tab` param.
// Importing it from the same module as the heavy detail component (which
// reaches lib/names.ts, and therefore tldts's public suffix list, through
// OverviewTab/SettingsTab) would force that whole module into the eager
// bundle regardless of how the route's `component` field is split — the
// exact regression scripts/check-chunks.mjs guards against.
export const TABS = ['overview', 'versions', 'attempts', 'deployments', 'settings'] as const;
export type Tab = (typeof TABS)[number];
