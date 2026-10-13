import { expect, it } from 'vitest';
import { notificationSourceId } from './identity';
it('canonicalizes aliases without merging distinct ChatLog events', () => {
  expect(notificationSourceId('did:ad:page#entry-1')).toBe(
    'atomic:page#entry-1',
  );
  expect(notificationSourceId('atomic:page?drive=home#entry-1')).toBe(
    'atomic:page#entry-1',
  );
  expect(notificationSourceId('atomic:page#entry-2')).not.toBe(
    notificationSourceId('atomic:page#entry-1'),
  );
});
