// The boot splash in index.html: the orbiting mark on an empty page. It sits
// outside #root, so it stays until something here says the page is ready.
//
// Most pages are ready at their first render and drop it straight away (see
// index.tsx). The demo is not: between the click on "Try Atomic" and a usable
// workspace it loads WebAssembly, opens storage, makes a guest identity and
// builds a drive. Each of those used to show its own screen (a blank page, a
// "Checking local storage…" card, a "Setting up your demo…" spinner). Keeping
// this one surface up until the workspace is ready replaces all of them, and
// the demo brings it back when it is started from inside the app.

const SPLASH_ID = 'boot-splash';
const LEAVING = 'boot-splash-leaving';
const REVEALING = 'boot-revealing';
const LEAVE_MS = 200;

let revealWaiters: (() => void)[] = [];
let leaveTimer: ReturnType<typeof setTimeout> | undefined;

function splash(): HTMLElement | null {
  return typeof document === 'undefined'
    ? null
    : document.getElementById(SPLASH_ID);
}

/** Whether the boot splash covers the page. */
export function isBootSplashVisible(): boolean {
  const element = splash();

  return !!element && !element.classList.contains(LEAVING);
}

/** The line under the mark. It fades in only if loading takes a while. */
export function setBootSplashCaption(text: string): void {
  const caption = splash()?.querySelector('.boot-caption');
  if (caption) caption.textContent = text;
}

/** Cover the page with the splash again, for a setup started in the app. */
export function showBootSplash(): void {
  const element = splash();
  if (!element) return;
  clearTimeout(leaveTimer);
  document.getElementById('root')?.classList.remove(REVEALING);
  element.classList.remove(LEAVING);
}

/**
 * Fade the splash out and bring the app in from behind it. Idempotent. The
 * element stays in the document, hidden, so the demo can show it again.
 */
export function hideBootSplash({ reveal = false } = {}): void {
  const element = splash();

  if (!element || element.classList.contains(LEAVING)) {
    flushRevealWaiters();

    return;
  }

  const root = document.getElementById('root');
  // The app arriving from behind the splash (a slight scale and fade) is for
  // the demo, whose workspace the splash was held for. An ordinary page load
  // just lets the splash fade: scaling the whole app for half a second moved
  // everything a page measured or clicked in that time.
  if (reveal) root?.classList.add(REVEALING);
  element.classList.add(LEAVING);

  leaveTimer = setTimeout(() => {
    root?.classList.remove(REVEALING);
    flushRevealWaiters();
  }, LEAVE_MS);
}

let holds = 0;
let lastBusyAt = 0;
let settleTimer: ReturnType<typeof setInterval> | undefined;

/**
 * Keep the splash up while something in the app shows its own loader (a
 * pane-level `<Spinner centered />`). Returns the release.
 */
export function holdBootSplash(): () => void {
  holds += 1;
  lastBusyAt = Date.now();
  let released = false;

  return () => {
    if (released) return;
    released = true;
    holds -= 1;
    lastBusyAt = Date.now();
  };
}

/**
 * Hide the splash once the app has shown no loader of its own for `quietMs`,
 * or after `maxMs` whatever happens. The splash is the one loader from the
 * first paint to the first real content, so nothing moves in between; the
 * quiet gap bridges one loader replacing another.
 */
export function hideBootSplashWhenSettled({
  quietMs = 100,
  maxMs = 8_000,
} = {}): void {
  if (settleTimer) return;
  const startedAt = Date.now();
  lastBusyAt = Math.max(lastBusyAt, startedAt);

  settleTimer = setInterval(() => {
    const now = Date.now();
    const settled = holds === 0 && now - lastBusyAt >= quietMs;

    if (!settled && now - startedAt < maxMs && isBootSplashVisible()) return;

    clearInterval(settleTimer);
    settleTimer = undefined;
    hideBootSplash();
  }, 25);
}

/** Resolves once the app is on screen with no splash in front of it. */
export function whenRevealed(): Promise<void> {
  if (!isBootSplashVisible() && !leaveTimerRunning()) {
    return Promise.resolve();
  }

  return new Promise(resolve => revealWaiters.push(resolve));
}

function leaveTimerRunning(): boolean {
  return !!document.getElementById('root')?.classList.contains(REVEALING);
}

function flushRevealWaiters(): void {
  const waiters = revealWaiters;
  revealWaiters = [];
  for (const resolve of waiters) resolve();
}

/** Two frames: long enough for React to have committed and the browser to
 *  have painted what it committed. */
export function afterNextPaint(): Promise<void> {
  return new Promise(resolve =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
  );
}
