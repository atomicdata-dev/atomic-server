type Handlers<Types extends string> = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key in Types]: (...args: any[]) => any;
};

/** Event manger, used to manage events and dispatch events to the correct handlers. */
export class EventManager<Types extends string, H extends Handlers<Types>> {
  private subscriptions = new Map<Types, Set<H[Types]>>();

  public register<T extends Types>(event: T, handler: H[T]) {
    const handlers = this.subscriptions.get(event) ?? new Set();
    handlers.add(handler);

    this.subscriptions.set(event, handlers);

    return () => {
      handlers.delete(handler);
    };
  }

  public async emit<T extends Types>(
    event: T,
    ...args: Parameters<H[T]>
  ): Promise<void> {
    if (!this.subscriptions.has(event)) return;

    const handlers = this.subscriptions.get(event);

    const wrap = async (handler: H[Types]) => {
      handler(...args);

      return;
    };

    if (!handlers) {
      return;
    }

    await Promise.allSettled([...handlers].map(handler => wrap(handler)));
  }

  public hasSubscriptions<T extends Types>(event: T): boolean {
    return this.subscriptions.has(event);
  }
}

/* EXAMPLE:

type EventTypes = 'exampleStart' | 'exampleEnd';

type EventHandlers = {
  exampleStart: (message: string) => void;
  exampleEnd: (animals: boolean[]) => void;
};

class Example {
  private emitter = new EventManager<EventTypes, EventHandlers>();

  public on<T extends EventTypes>(event: T, cb: EventHandlers[T]) {
    return this.emitter.register(event, cb);
  }

  public doSomething() {
    this.emitter.emit('exampleEnd', [true]);
  }
}
*/
