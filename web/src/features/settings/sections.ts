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
  { slug: 'issuance-defaults', label: 'Issuance defaults' },
  { slug: 'backup', label: 'Backup and keys' },
] as const;
export type SectionSlug = (typeof SECTIONS)[number]['slug'];
