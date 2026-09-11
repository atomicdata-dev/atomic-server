import { afterEach, describe, expect, it, vi } from 'vitest';
import { Resource, type SaveResult } from './resource.js';
import { SaveStatusCoordinator } from './save-status-coordinator.js';

function setup() {
  const callbacks = new Set<() => void>();
  let pending = 0;
  let connected = false;
  const entries = new Map<
    string,
    { blocked?: boolean; lastAttemptError?: string }
  >();
  const onError = vi.fn();
  const coordinator = new SaveStatusCoordinator({
    getOutboxEntry: subject => entries.get(subject),
    isConnected: () => connected,
    changePending: delta => {
      pending += delta;
      callbacks.forEach(callback => callback());
    },
    subscribeSync: callback => {
      callbacks.add(callback);

      return () => {
        callbacks.delete(callback);
      };
    },
    onError,
  });

  return {
    coordinator,
    entries,
    onError,
    pending: () => pending,
    connect: () => {
      connected = true;
    },
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('SaveStatusCoordinator', () => {
  it('keeps another owner pending when an observer disposes and one scheduler cancels', async () => {
    vi.useFakeTimers();
    const { coordinator, pending } = setup();
    const resource = new Resource('_new:owners');
    let finish!: () => void;
    const saving = new Promise<SaveResult>(resolve => {
      finish = () => resolve('persisted');
    });
    const save = vi.spyOn(resource, 'save').mockReturnValue(saving);
    const firstObserver = vi.fn();
    const secondObserver = vi.fn();
    const unsubscribeFirst = coordinator.subscribe(resource, firstObserver);
    const unsubscribeSecond = coordinator.subscribe(resource, secondObserver);
    const first = coordinator.createScheduler(resource);
    const second = coordinator.createScheduler(resource);
    first.schedule(100);
    second.schedule(200);
    expect(pending()).toBe(2);
    resource.setSubject('did:ad:owners');
    expect(coordinator.getState(resource).scheduledCount).toBe(2);
    unsubscribeFirst();
    unsubscribeFirst();
    firstObserver.mockClear();
    first.cancel();
    const flushed = second.flush();
    await Promise.resolve();
    expect(save).toHaveBeenCalledTimes(1);
    expect(pending()).toBe(1);
    expect(coordinator.getState(resource).scheduledCount).toBe(1);
    expect(firstObserver).not.toHaveBeenCalled();
    expect(secondObserver).toHaveBeenCalled();
    finish();
    await flushed;
    expect(pending()).toBe(0);
    expect(coordinator.getState(resource).kind).toBe('idle');
    unsubscribeSecond();
  });

  it('derives immutable snapshots from the current outbox entry and connection', () => {
    const { coordinator, entries, connect } = setup();
    const resource = new Resource('_new:status');
    const idle = coordinator.getState(resource);
    expect(coordinator.getState(resource)).toBe(idle);
    expect(Object.isFrozen(idle)).toBe(true);
    resource.setSubject('did:ad:status');
    entries.set(resource.subject, {});
    const offline = coordinator.getState(resource);
    expect(offline).toMatchObject({ kind: 'queued', reason: 'offline' });
    expect(coordinator.getState(resource)).toBe(offline);
    connect();
    expect(coordinator.getState(resource)).toMatchObject({
      kind: 'queued',
      reason: 'retry',
    });
    entries.set(resource.subject, {
      blocked: true,
      lastAttemptError: 'Denied',
    });
    expect(coordinator.getState(resource)).toMatchObject({
      kind: 'error',
      error: 'Denied',
      reason: undefined,
    });
    const saving = vi.spyOn(resource, 'isSaving', 'get').mockReturnValue(true);
    expect(coordinator.getState(resource).kind).toBe('saving');
    saving.mockRestore();
    entries.delete(resource.subject);
    expect(coordinator.getState(resource)).toEqual(idle);
    expect(offline.reason).toBe('offline');
    expect(idle.kind).toBe('idle');
  });

  it('settles accounting on failure and delegates error handling without retrying persistence', async () => {
    vi.useFakeTimers();
    const { coordinator, pending, onError } = setup();
    const resource = new Resource('_new:failed');
    const error = new Error('Save failed');
    const save = vi.spyOn(resource, 'save').mockRejectedValue(error);
    const scheduler = coordinator.createScheduler(resource);
    scheduler.schedule(100);
    await scheduler.flush();
    expect(pending()).toBe(0);
    expect(onError).toHaveBeenCalledWith(error);
    expect(save).toHaveBeenCalledTimes(1);
    await vi.runAllTimersAsync();
    expect(save).toHaveBeenCalledTimes(1);
  });
});
