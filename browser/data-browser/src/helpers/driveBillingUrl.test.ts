import { describe, expect, it } from 'vitest';
import { driveBillingUrl } from './driveBillingUrl';

describe('drive billing links', () => {
  it('keeps the exact selected drive on the account portal', () => {
    const url = new URL(
      driveBillingUrl(
        'https://staging.atomicserver.eu/',
        'did:ad:drive+with/slash',
      ),
    );
    expect(url.origin).toBe('https://staging.atomicserver.eu');
    expect(url.pathname).toBe('/billing');
    expect(url.searchParams.get('drive')).toBe('did:ad:drive+with/slash');
  });
  it('opens the drive picker when there is no current drive', () => {
    expect(driveBillingUrl('https://staging.atomicserver.eu')).toBe(
      'https://staging.atomicserver.eu/billing',
    );
  });
});
