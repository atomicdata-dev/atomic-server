import { afterEach, describe, it, vi } from 'vitest';
import { EventManager } from './EventManager.js';
enum Events {
  Click = 'click',
  LotteryWon = 'lotterywon',
}

type EventHandlers = {
  [Events.Click]: (message: string) => void;
  [Events.LotteryWon]: (lotteryNumber: number[]) => void;
};

describe('EventManager', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('registers events', ({ expect }) => {
    const eventManager = new EventManager<Events, EventHandlers>();

    const cb = vi.fn();
    eventManager.register(Events.Click, cb);

    eventManager.emit(Events.Click, 'Hello');

    expect(cb).toHaveBeenCalledWith('Hello');
  });

  it('calls the correct handlers', ({ expect }) => {
    const eventManager = new EventManager<Events, EventHandlers>();

    const cb = vi.fn();
    eventManager.register(Events.Click, cb);

    eventManager.emit(Events.Click, 'Hello');
    eventManager.emit(Events.LotteryWon, [1, 2, 3]);

    expect(cb).toHaveBeenCalledTimes(1);
  });

  it('unsubscribes', ({ expect }) => {
    const eventManager = new EventManager<Events, EventHandlers>();

    const cb = vi.fn();
    const unsub = eventManager.register(Events.Click, cb);

    eventManager.emit(Events.Click, 'Hello');
    unsub();
    eventManager.emit(Events.Click, 'Bye');

    expect(cb).toHaveBeenCalledTimes(1);
  });
});
