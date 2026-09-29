import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { CertValidity } from '@/components/ValidityBar';
import { iso, makeCert } from '@/test/fixtures';
import { renderUI } from '@/test/render';

// Task 4 (R12 deviation, 5a-facts.md: ariWindow stays null for a private-CA
// certificate): no component change — ValidityBar already draws the ARI
// bracket and row only when `ari` is non-null (validityGeometry's
// `ariOutside` short-circuits on `!ari`), so a null ariWindow already
// renders no marker. makeCert()'s own default is `ariWindow: null`.
it('private CA has no ARI marker', () => {
  renderUI(<CertValidity cert={makeCert({ ariWindow: null })} size="full" />);
  expect(screen.queryByText(/ARI window/)).toBeNull();
});

it('an acme certificate with an ARI window draws the marker (contrast)', () => {
  renderUI(<CertValidity cert={makeCert({ ariWindow: { start: iso(0), end: iso(20), checkedAt: iso(0) } })} size="full" />);
  expect(screen.getByText(/ARI window/)).toBeInTheDocument();
});
