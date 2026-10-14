import { describe, expect, it } from 'vitest';
import {
  assertPublicDestination,
  isBlockedIp,
  parseDestination,
  UnsafeUrlError,
} from './url-guard.js';

describe('isBlockedIp', () => {
  it.each([
    '127.0.0.1',
    '127.255.255.254',
    '10.0.0.5',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.10',
    '169.254.169.254', // cloud metadata
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '255.255.255.255',
    '::1',
    '::',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    '::ffff:127.0.0.1', // IPv4-mapped loopback
    '::ffff:7f00:1', // same, hex form
    '::ffff:169.254.169.254',
    '64:ff9b::7f00:1', // NAT64 pointing to 127.0.0.1
    'not-an-ip',
  ])('blocks %s', (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '2606:4700:4700::1111'])(
    'allows the public address %s',
    (ip) => {
      expect(isBlockedIp(ip)).toBe(false);
    },
  );
});

describe('parseDestination', () => {
  it.each([
    ['http://example.com/hook', 'https'],
    ['ftp://example.com/hook', 'https'],
    ['https://user:secret@example.com/hook', 'credentials'],
    ['https://localhost/hook', 'not allowed'],
    ['https://api.localhost/hook', 'not allowed'],
    ['https://service.internal/hook', 'not allowed'],
    ['https://printer.local/hook', 'not allowed'],
    ['https://127.0.0.1/hook', 'IP'],
    ['https://2130706433/hook', 'IP'], // decimal form of 127.0.0.1
    ['https://0x7f.1/hook', 'IP'], // hex form
    ['https://0177.0.0.1/hook', 'IP'], // octal form
    ['https://127.1/hook', 'IP'], // short form
    ['https://[::1]/hook', 'IP'],
    ['https://[::ffff:127.0.0.1]/hook', 'IP'],
    ['https://169.254.169.254/latest/meta-data', 'IP'],
    ['https://10.0.0.1/hook', 'IP'],
    ['https://LOCALHOST./hook', 'not allowed'], // case and trailing dot
    ['not a url', 'valid'],
  ])('rejects %s', (raw, reason) => {
    expect(() => parseDestination(raw)).toThrow(UnsafeUrlError);
    expect(() => parseDestination(raw)).toThrow(new RegExp(reason));
  });

  it('rejects very long URLs', () => {
    expect(() => parseDestination(`https://example.com/${'a'.repeat(3000)}`)).toThrow(/too long/);
  });

  it('accepts a normal https URL', () => {
    expect(parseDestination('https://example.com/hooks/stock?x=1').hostname).toBe('example.com');
  });

  it('allows http and local addresses only in development mode', () => {
    expect(parseDestination('http://127.0.0.1:4000/hook', true).port).toBe('4000');
    expect(() => parseDestination('http://127.0.0.1:4000/hook', false)).toThrow(UnsafeUrlError);
  });
});

describe('assertPublicDestination (DNS)', () => {
  const resolverTo =
    (...addresses: string[]) =>
    async () =>
      addresses;

  it('accepts a name that resolves to public addresses', async () => {
    const result = await assertPublicDestination('https://hooks.example.com/x', {
      resolver: resolverTo('93.184.216.34', '2606:4700:4700::1111'),
    });
    expect(result.addresses).toHaveLength(2);
  });

  it('rejects a name that resolves to a private address', async () => {
    await expect(
      assertPublicDestination('https://evil.example.com/x', { resolver: resolverTo('10.0.0.8') }),
    ).rejects.toThrow(/private or reserved/);
  });

  it('rejects a name that resolves to the cloud metadata address', async () => {
    await expect(
      assertPublicDestination('https://evil.example.com/x', {
        resolver: resolverTo('169.254.169.254'),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects when only one of several addresses is private', async () => {
    await expect(
      assertPublicDestination('https://mixed.example.com/x', {
        resolver: resolverTo('93.184.216.34', '127.0.0.1'),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects a name that cannot be resolved', async () => {
    await expect(
      assertPublicDestination('https://nope.example.com/x', {
        resolver: async () => {
          throw new Error('ENOTFOUND');
        },
      }),
    ).rejects.toThrow(/cannot be resolved/);
    await expect(
      assertPublicDestination('https://empty.example.com/x', { resolver: resolverTo() }),
    ).rejects.toThrow(/cannot be resolved/);
  });

  it('skips the checks in development mode', async () => {
    const result = await assertPublicDestination('http://127.0.0.1:4000/hook', {
      allowPrivateDestinations: true,
    });
    expect(result.url.port).toBe('4000');
  });
});
