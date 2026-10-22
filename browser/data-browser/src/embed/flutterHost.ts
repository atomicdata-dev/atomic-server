import type { NativeChannel } from '@tomic/lib';

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void };

/**
 * The channel inside the Flutter app. A call is a message on Flutter's
 * `JavaScriptChannel` (`{id, method, args}`); the app answers by calling
 * `window.__atomicReply(id, ok, payload)`, `payload` being the JSON of the
 * result, or the error text.
 */
export function createFlutterHost(channel: {
  postMessage(message: string): void;
}): NativeChannel {
  const pending = new Map<number, Pending>();
  let next = 0;

  Object.assign(window, {
    __atomicReply(id: number, ok: boolean, payload: string) {
      const waiting = pending.get(id);

      if (!waiting) return;

      pending.delete(id);

      if (ok) {
        waiting.resolve(JSON.parse(payload));
      } else {
        waiting.reject(new Error(payload));
      }
    },
  });

  return {
    call(method, args) {
      return new Promise((resolve, reject) => {
        const id = ++next;

        pending.set(id, { resolve, reject });
        channel.postMessage(JSON.stringify({ id, method, args }));
      });
    },
  };
}
