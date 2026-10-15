import { describe, expect, it } from 'vitest';
import { matchesSubscription, stableStringify } from './matching.js';

describe('matchesSubscription', () => {
  it.each([
    ['*', 'order.paid', true],
    ['*', 'anything', true],
    ['order.paid', 'order.paid', true],
    ['order.paid', 'order.refunded', false],
    ['order.paid', 'order.paid.extra', false],
    ['invoice.*', 'invoice.paid', true],
    ['invoice.*', 'invoice.payment.failed', true],
    ['invoice.*', 'invoice', false], // the prefix must be followed by a dot
    ['invoice.*', 'invoices.paid', false],
    ['invoice.*', 'xinvoice.paid', false],
    ['order', 'order.paid', false],
  ])('pattern %s against %s gives %s', (pattern, type, expected) => {
    expect(matchesSubscription(pattern, type)).toBe(expected);
  });
});

describe('stableStringify', () => {
  it('does not depend on key order', () => {
    expect(stableStringify({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } })).toBe(
      stableStringify({ a: { c: [3, { y: 2, z: 1 }], d: 2 }, b: 1 }),
    );
  });

  it('tells different values apart', () => {
    expect(stableStringify({ amount: 100 })).not.toBe(stableStringify({ amount: '100' }));
    expect(stableStringify({ a: [1, 2] })).not.toBe(stableStringify({ a: [2, 1] }));
  });
});
