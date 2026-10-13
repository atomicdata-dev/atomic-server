import { afterEach, expect, it } from 'vitest';
import * as Sentry from '@sentry/react';
import { submitFeedback } from './feedback';
import { sanitizeFeedbackEvent } from './feedback-privacy';

afterEach(async () => {
  await Sentry.close();
});

it('sends full diagnostics through the SDK as an isolated attachment', async () => {
  type Options = NonNullable<Parameters<typeof Sentry.init>[0]>;
  type Transport = ReturnType<NonNullable<Options['transport']>>;
  const envelopes: Parameters<Transport['send']>[0][] = [];
  Sentry.init({
    dsn: 'https://key@example.com/123',
    defaultIntegrations: false,
    transport: () => ({
      send: async envelope => {
        envelopes.push(envelope);

        return { statusCode: 200 };
      },
      flush: async () => true,
    }),
  });
  Sentry.addEventProcessor(sanitizeFeedbackEvent);
  const diagnostics = JSON.stringify({
    events: Array(500).fill({ code: 'save-persisted', note: 'synthetic é' }),
  });
  await submitFeedback('Attachment verification', '', 'sidebar', diagnostics);
  await submitFeedback('Without diagnostics', '');
  expect(envelopes).toHaveLength(2);
  const items = envelopes[0][1];
  expect(items[0][0].type).toBe('feedback');
  expect(items[0][1]).toMatchObject({
    contexts: { feedback: { message: 'Attachment verification' } },
  });
  expect(items[1][0]).toMatchObject({
    type: 'attachment',
    filename: 'diagnostics.json',
    content_type: 'application/json',
    length: new TextEncoder().encode(diagnostics).length,
  });
  expect(new TextDecoder().decode(items[1][1] as Uint8Array)).toBe(diagnostics);
  expect(envelopes[1][1]).toHaveLength(1);
});
