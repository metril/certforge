import { z } from 'zod';

// Split out of SettingsPage.tsx (Task 14 fix): `$section.tsx`'s `beforeLoad`
// needs only the slug list, not the page itself. Importing SECTIONS from
// SettingsPage.tsx pulled that whole module — and everything it renders,
// including IssuanceDefaultsSection -> issuanceFields ->
// VerificationRulesEditor -> lib/coverage -> lib/names -> tldts — into the
// route's eager/critical half, defeating TanStack Router's autoCodeSplitting
// and landing tldts in the main chunk regardless of how the certificate
// wizard route itself is loaded.
export const SECTIONS = [
  { slug: 'general', label: 'General' },
  { slug: 'access', label: 'Access' },
  { slug: 'authentication', label: 'Authentication' },
  { slug: 'issuance-defaults', label: 'Issuance defaults' },
  { slug: 'backup', label: 'Backup and keys' },
] as const;
export type SectionSlug = (typeof SECTIONS)[number]['slug'];

export const ACCESS_TABS = ['users', 'bindings', 'keys'] as const;
export type AccessTab = (typeof ACCESS_TABS)[number];

// Search params shared by /settings/$section; only Access reads them.
// `q` (D5 ruling): URL-synced text filter for the Users tab, mirroring the
// `q` param on the certificates list (features/certificates/list/search.ts).
export const settingsSearch = z.object({
  tab: z.enum(ACCESS_TABS).optional().catch(undefined),
  type: z.enum(['user', 'oidc_group', 'apikey']).optional().catch(undefined),
  // orgId (D5 ruling, Task 4 fix round 1): URL-synced org filter for the
  // Role bindings tab.
  orgId: z.string().optional().catch(undefined),
  q: z.string().optional().catch(undefined),
});
export type SettingsSearch = z.infer<typeof settingsSearch>;
