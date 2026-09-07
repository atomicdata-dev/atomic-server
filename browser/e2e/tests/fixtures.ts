import { test as base, expect, type BrowserContext } from '@playwright/test';

export * from '@playwright/test';

type Kind = 'warning' | 'error' | 'pageerror';
type Entry = { kind: Kind; message: string; url: string };
type Expected = {
  kind: Kind;
  message: RegExp;
  reason: string;
  count: number;
  seen: number;
  url?: RegExp;
};

/** No global allowlist: expected failures belong to the test that causes them. */
export const test = base.extend<{
  browserDiagnostics: {
    expect: (
      kind: Kind,
      message: RegExp,
      reason: string,
      count?: number,
      url?: RegExp,
    ) => void;
  };
}>({
  browserDiagnostics: [
    async ({ browser, context: defaultContext }, use, testInfo) => {
      const entries: (Entry & { expected: boolean })[] = [];
      const expected: Expected[] = [];
      const cleanups: (() => void)[] = [];
      const watched = new Set<BrowserContext>();
      const ownedContexts = new Set<BrowserContext>();

      const record = (entry: Entry) => {
        const match = expected.find(rule => {
          rule.message.lastIndex = 0;
          if (rule.url) rule.url.lastIndex = 0;

          return (
            rule.kind === entry.kind &&
            rule.seen < rule.count &&
            rule.message.test(entry.message) &&
            (!rule.url || rule.url.test(entry.url))
          );
        });
        if (match) match.seen++;
        entries.push({ ...entry, expected: !!match });
      };

      const watch = (context: BrowserContext) => {
        if (watched.has(context)) return;
        watched.add(context);

        const onConsole = (msg: import('@playwright/test').ConsoleMessage) => {
          const kind = msg.type();

          if (kind === 'warning' || kind === 'error') {
            record({ kind, message: msg.text(), url: msg.location().url });
          }
        };

        const onError = (event: import('@playwright/test').WebError) => {
          record({
            kind: 'pageerror',
            message: event.error().stack ?? event.error().message,
            url: event.page()?.url() ?? '',
          });
        };

        context.on('console', onConsole);
        context.on('weberror', onError);
        cleanups.push(() => {
          context.off('console', onConsole);
          context.off('weberror', onError);
        });
      };

      // Depend on context so assertions run BEFORE Playwright closes it. The
      // auto fixture still runs before page setup/navigation. Wrap creation so additional
      // users, popups and tabs are observed before their first navigation too.
      const newContext = browser.newContext;

      browser.newContext = async options => {
        const context = await newContext.call(browser, options);
        ownedContexts.add(context);
        watch(context);

        return context;
      };

      watch(defaultContext);
      browser.contexts().forEach(watch);

      try {
        await use({
          expect(kind, message, reason, count = 1, url) {
            if (!reason.trim() || !Number.isInteger(count) || count < 1) {
              throw new Error(
                'Expected diagnostics require a reason and a positive integer count',
              );
            }

            expected.push({ kind, message, reason, count, url, seen: 0 });
          },
        });
      } finally {
        browser.newContext = newContext;
        cleanups.forEach(cleanup => cleanup());
        // Match Playwright's default-context teardown for extra test-owned
        // contexts. Otherwise their live tabs leak into the next test.
        await Promise.all([...ownedContexts].map(context => context.close()));

        if (entries.length || expected.length) {
          await testInfo.attach('browser-diagnostics', {
            body: JSON.stringify(
              {
                entries,
                expectations: expected.map(rule => ({
                  ...rule,
                  message: rule.message.source,
                  url: rule.url?.source,
                })),
              },
              null,
              2,
            ),
            contentType: 'application/json',
          });
        }

        const unexpected = entries.filter(entry => !entry.expected);
        const missing = expected.filter(rule => rule.seen !== rule.count);
        expect(
          unexpected.slice(0, 20),
          `Unexpected browser warnings/errors (${unexpected.length}); first 20 shown, full browser-diagnostics attached`,
        ).toEqual([]);
        expect(missing, 'Expected diagnostic count did not match').toEqual([]);
      }
    },
    { auto: true },
  ],
});

export default test;
