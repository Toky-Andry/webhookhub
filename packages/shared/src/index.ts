/** Constants shared by the API, the worker and the dashboard. */
export const MAX_DELIVERY_ATTEMPTS = 8;

/** Delay before each retry, in seconds (attempt 2 to 8). A random jitter is added at runtime. */
export const RETRY_DELAYS_SECONDS = [10, 60, 300, 1800, 7200, 21600, 43200] as const;

export const DELIVERY_STATUSES = ['pending', 'sending', 'retrying', 'delivered', 'dead'] as const;
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number];
