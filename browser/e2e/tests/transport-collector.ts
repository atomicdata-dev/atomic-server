import type { BrowserContext, Page, WebSocket } from '@playwright/test';

type FrameMetadata = {
  at: number;
  direction: 'sent' | 'received' | 'closed';
  bytes: number;
  tag: number | 'text' | undefined;
};

/** Retains bounded frame metadata, including closed pages, never frame contents. */
export class TransportCollector {
  private events = new Map<Page, FrameMetadata[]>();
  private contexts = new Set<BrowserContext>();
  private watchedPages = new Set<Page>();
  private cleanups = new Set<() => void>();

  start(context: BrowserContext): void {
    if (this.contexts.has(context)) return;
    this.contexts.add(context);
    const watchPage = (page: Page) => this.watchPage(page);
    context.pages().forEach(watchPage);
    context.on('page', watchPage);
    this.cleanups.add(() => context.off('page', watchPage));
  }

  private watchPage(page: Page): void {
    if (this.watchedPages.has(page)) return;
    this.watchedPages.add(page);
    if (!this.events.has(page)) this.events.set(page, []);

    const record = (
      direction: FrameMetadata['direction'],
      payload: string | Buffer,
    ) => {
      const events = this.events.get(page)!;
      events.push({
        at: Date.now(),
        direction,
        bytes: Buffer.byteLength(payload),
        tag: typeof payload === 'string' ? 'text' : payload[0],
      });
      if (events.length > 30) events.shift();
    };

    const onSocket = (socket: WebSocket) => {
      const sent = ({ payload }: { payload: string | Buffer }) =>
        record('sent', payload);
      const received = ({ payload }: { payload: string | Buffer }) =>
        record('received', payload);

      const cleanup = () => {
        socket.off('framesent', sent);
        socket.off('framereceived', received);
        socket.off('close', closed);
        this.cleanups.delete(cleanup);
      };

      const closed = () => {
        record('closed', '');
        cleanup();
      };

      socket.on('framesent', sent);
      socket.on('framereceived', received);
      socket.on('close', closed);
      this.cleanups.add(cleanup);
    };

    page.on('websocket', onSocket);
    this.cleanups.add(() => page.off('websocket', onSocket));
  }

  snapshot(page: Page): FrameMetadata[] {
    return (this.events.get(page) ?? []).map(event => ({ ...event }));
  }

  pages(): Page[] {
    return [...this.events.keys()];
  }

  dispose(): void {
    this.cleanups.forEach(cleanup => cleanup());
    this.cleanups.clear();
    this.contexts.clear();
    this.watchedPages.clear();
  }
}
