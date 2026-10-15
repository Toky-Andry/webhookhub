/**
 * Does a subscription pattern match an event type?
 *   "*"          matches every event
 *   "invoice.*"  matches "invoice.paid" and "invoice.payment.failed", but not "invoice"
 *   "order.paid" matches only "order.paid"
 */
export function matchesSubscription(pattern: string, eventType: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('.*')) return eventType.startsWith(pattern.slice(0, -1)); // keeps the dot
  return pattern === eventType;
}

/** JSON with sorted keys, so that two equal payloads always give the same string. */
export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}
