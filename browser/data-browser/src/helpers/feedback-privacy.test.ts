import { expect, it } from 'vitest';
import { sanitizeFeedbackEvent } from './feedback-privacy';

it('excludes inherited private context from the final feedback event', () => {
  const report = sanitizeFeedbackEvent({
    type: 'feedback',
    event_id: 'event',
    release: 'build',
    request: { url: 'https://private.example/SECRET_URL' },
    breadcrumbs: [{ message: 'SECRET_CONSOLE' }],
    user: { email: 'SECRET_EMAIL' },
    extra: { data: 'SECRET_TEXT' },
    tags: { path: 'SECRET_PATH' },
    contexts: {
      private: { value: 'SECRET_CONTEXT' },
      feedback: {
        message: 'Explicit feedback',
        contact_email: 'reply@example.com',
        url: 'SECRET_URL',
        name: 'SECRET_NAME',
      },
    },
  });
  expect(JSON.stringify(report)).not.toContain('SECRET');
  expect(report.contexts?.feedback).toEqual({
    message: 'Explicit feedback',
    contact_email: 'reply@example.com',
    source: 'sidebar',
    url: '',
  });
});

it('retains browser and OS metadata without unrelated request or context data', () => {
  const report = sanitizeFeedbackEvent({
    type: 'feedback',
    platform: 'javascript',
    level: 'info',
    request: {
      url: 'SECRET_URL',
      headers: {
        'User-Agent': 'Mozilla/5.0 test-browser',
        Cookie: 'SECRET_COOKIE',
        Referer: 'SECRET_REFERER',
      },
      data: 'SECRET_BODY',
    },
    contexts: {
      browser: { name: 'Chrome', version: '153.0', private: 'SECRET_BROWSER' },
      os: { name: 'macOS', version: '15.0', private: 'SECRET_OS' },
      device: { name: 'SECRET_DEVICE' },
      feedback: { message: 'Problem' },
    },
  });
  expect(report.platform).toBe('javascript');
  expect(report.level).toBe('info');
  expect(report.contexts?.browser).toEqual({
    name: 'Chrome',
    version: '153.0',
  });
  expect(report.contexts?.os).toEqual({ name: 'macOS', version: '15.0' });
  expect(report.request).toEqual({
    headers: { 'User-Agent': 'Mozilla/5.0 test-browser' },
  });
  expect(JSON.stringify(report)).not.toContain('SECRET');
});

it('keeps a known report source and replaces anything else', () => {
  const source = (value: unknown) =>
    sanitizeFeedbackEvent({
      type: 'feedback',
      contexts: { feedback: { message: 'Problem', source: value } },
    }).contexts?.feedback?.source;

  expect(source('ai-chat')).toBe('ai-chat');
  expect(source('error')).toBe('error');
  expect(source('SECRET_SOURCE')).toBe('sidebar');
});

it('keeps only the hashed user id, never email, IP or username', () => {
  const report = sanitizeFeedbackEvent({
    type: 'feedback',
    user: {
      id: 'a1b2c3d4e5f60718',
      email: 'SECRET_EMAIL',
      ip_address: 'SECRET_IP',
      username: 'SECRET_USER',
    },
    contexts: { feedback: { message: 'Problem' } },
  });
  expect(report.user).toEqual({ id: 'a1b2c3d4e5f60718' });
  expect(JSON.stringify(report)).not.toContain('SECRET');
});

it('sends no user when the agent is not identified', () => {
  const report = sanitizeFeedbackEvent({
    type: 'feedback',
    user: { email: 'SECRET_EMAIL', ip_address: 'SECRET_IP' },
    contexts: { feedback: { message: 'Problem' } },
  });
  expect(report.user).toBeUndefined();
});

it('keeps console and click breadcrumbs, drops those that carry URLs, and caps at 30', () => {
  const categories = [
    'console',
    'ui.click',
    'navigation',
    'fetch',
    'xhr',
    'history',
  ];
  const report = sanitizeFeedbackEvent({
    type: 'feedback',
    breadcrumbs: [
      ...categories.map(category => ({
        category,
        message: `crumb ${category}`,
        data: { url: 'SECRET_URL' },
      })),
      { message: 'no category' },
    ],
    contexts: { feedback: { message: 'Problem' } },
  });
  expect(report.breadcrumbs?.map(crumb => crumb.category)).toEqual([
    'console',
    'ui.click',
  ]);

  const many = sanitizeFeedbackEvent({
    type: 'feedback',
    breadcrumbs: Array.from({ length: 50 }, (_, i) => ({
      category: 'console',
      message: `log ${i}`,
    })),
    contexts: { feedback: { message: 'Problem' } },
  });
  expect(many.breadcrumbs).toHaveLength(30);
  expect(many.breadcrumbs?.[0]?.message).toBe('log 20');
  expect(many.breadcrumbs?.at(-1)?.message).toBe('log 49');
});
