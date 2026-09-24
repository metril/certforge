// Type-only assertions: no runtime behavior, checked by vitest's typecheck
// pool (vite.config.ts `test.typecheck.enabled`) as part of `npm test`. These
// pin the shape of aliases Task 10 imports, so removing or reshaping one
// fails the test run, not just `tsc --noEmit`.
import { expectTypeOf, it } from 'vitest';
import type { EffectiveIssuanceDefaults, EffectiveMap, EffectiveValue, Source, VerificationMethod, VerificationRule } from './types';

it('EffectiveMap is EffectiveIssuanceDefaults', () => {
  expectTypeOf<EffectiveMap>().toEqualTypeOf<EffectiveIssuanceDefaults>();
});

it('EffectiveValue is a non-nullable field of EffectiveIssuanceDefaults', () => {
  expectTypeOf<EffectiveValue>().toEqualTypeOf<NonNullable<EffectiveIssuanceDefaults[keyof EffectiveIssuanceDefaults]>>();
});

it('VerificationMethod is VerificationRule[\'method\']', () => {
  expectTypeOf<VerificationMethod>().toEqualTypeOf<VerificationRule['method']>();
});

it('Source includes cert', () => {
  expectTypeOf<Source>().toEqualTypeOf<'default' | 'global' | 'org' | 'cert'>();
});
