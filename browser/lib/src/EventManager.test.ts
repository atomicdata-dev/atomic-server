import { jest, describe, it, expect } from 'bun:test';
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
  it('registers events', () => {
    const eventManager = new EventManager<Events, EventHandlers>();

    const cb = jest.fn();
    eventManager.register(Events.Click, cb);

    eventManager.emit(Events.Click, 'Hello');

    expect(cb).toHaveBeenCalledWith('Hello');
  });

  it('calls the correct handlers', () => {
    const eventManager = new EventManager<Events, EventHandlers>();

    const cb = jest.fn();
    eventManager.register(Events.Click, cb);

    eventManager.emit(Events.Click, 'Hello');
    eventManager.emit(Events.LotteryWon, [1, 2, 3]);

    expect(cb).toHaveBeenCalledTimes(1);
  });

  it('unsubscribes', () => {
    const eventManager = new EventManager<Events, EventHandlers>();

    const cb = jest.fn();
    const unsub = eventManager.register(Events.Click, cb);

    eventManager.emit(Events.Click, 'Hello');
    unsub();
    eventManager.emit(Events.Click, 'Bye');

    expect(cb).toHaveBeenCalledTimes(1);
  });
});
