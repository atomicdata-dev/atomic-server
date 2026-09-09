// @wc-ignore-file
/** Transport and lifetime only. Adapters must authorize before reading or writing. */
export interface FrameSession {
  isActive(): boolean;
  post(message: unknown): void;
  watch(key: string, subscribe: () => () => void): void;
  unwatch(key: string): void;
}

/** One owner for null-origin iframe messaging, theme and subscription cleanup. */
export class FrameBridge {
  private generation = 0;
  private closed = false;
  private subscriptions = new Map<string, () => void>();

  constructor(
    private frame: HTMLIFrameElement,
    private handle: (data: unknown, session: FrameSession) => void,
    private css = '',
    private host: Pick<
      Window,
      'addEventListener' | 'removeEventListener'
    > = window,
  ) {
    host.addEventListener('message', this.receive);
    frame.addEventListener('load', this.loaded);
  }

  setStyle(css: string): void {
    this.css = css;
    this.session().post({ type: '__atomic_style', css });
  }

  private session(): FrameSession {
    const generation = this.generation;
    const target = this.frame.contentWindow;
    const active = () =>
      !this.closed &&
      generation === this.generation &&
      target === this.frame.contentWindow;

    return {
      isActive: active,
      post: message => {
        if (active()) target?.postMessage(message, '*');
      },
      watch: (key, subscribe) => {
        if (active() && !this.subscriptions.has(key))
          this.subscriptions.set(key, subscribe());
      },
      unwatch: key => {
        if (!active()) return;
        this.subscriptions.get(key)?.();
        this.subscriptions.delete(key);
      },
    };
  }

  private receive = (event: MessageEvent): void => {
    if (
      this.closed ||
      !this.frame.contentWindow ||
      event.source !== this.frame.contentWindow
    )
      return;
    const data: unknown = event.data;
    if (!data || typeof data !== 'object') return;

    if ('type' in data && data.type === '__atomic_plugin_ready') {
      this.release();
      this.setStyle(this.css);

      return;
    }

    this.handle(data, this.session());
  };

  private loaded = (): void => {
    this.setStyle(this.css);
  };

  private release(): void {
    this.generation++;
    this.subscriptions.forEach(unsubscribe => unsubscribe());
    this.subscriptions.clear();
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.host.removeEventListener('message', this.receive);
    this.frame.removeEventListener('load', this.loaded);
    this.release();
  }
}
