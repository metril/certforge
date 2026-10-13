import { expect, it } from 'vitest';
import type { DeployTarget } from '@/api/types';
import { verifyDefault } from './verifyDefault';

const t = (type: string, config: Record<string, unknown> = {}) => ({ type, config }) as unknown as DeployTarget;

it('reads host and port from the url', () => {
  expect(verifyDefault(t('pfsense', { url: 'https://fw.lan:8443/api' }))).toEqual({ host: 'fw.lan', port: '8443' });
});
it('defaults the port to 443', () => {
  expect(verifyDefault(t('truenas', { url: 'https://nas.lan' }))).toEqual({ host: 'nas.lan', port: '443' });
});
it('returns empty for a bad url and for ssh', () => {
  expect(verifyDefault(t('routeros', { url: 'nope' }))).toEqual({ host: '', port: '443' });
  expect(verifyDefault(t('ssh', { host: 'x' }))).toEqual({ host: '', port: '443' });
});
it('is null for vault-kv', () => {
  expect(verifyDefault(t('vault-kv'))).toBeNull();
});

it('uses the host of a pikvm target, port 443', () => {
  expect(verifyDefault(t('pikvm', { host: 'kvm.lan' }))).toEqual({ host: 'kvm.lan', port: '443' });
});
