import { expect, it } from 'vitest';
import { hostPort } from './CaKindBody';

it('accepts host, host:port, [v6]:port and bare IPv6', () => {
  for (const v of ['1.1.1.1', '1.1.1.1:53', 'dns.example.com:5353', 'localhost', '[::1]:53', '[2001:db8::1]', '2001:db8::1', 'a', 'dns.google.', 'dns.google.:53', '[fe80::1%eth0]:53', '[fe80::1%eth0]']) expect(hostPort(v), v).toBeNull();
});

it('rejects garbage and out-of-range ports', () => {
  for (const v of ['[[]]', ':::', '-', 'a b', 'host:0', 'host:65536', '1.1.1.1:99999', '[::1]:0', '[::1]:70000', 'host:', '..:1', 'a:b:c:z']) expect(hostPort(v), v).not.toBeNull();
});
