// @wc-ignore-file
import type { FrameSession } from './FrameBridge';

/** Translate compatibility replies into the public v1 wire contract. */
export function viewSession(
  session: FrameSession,
  id: string | number,
): FrameSession {
  return {
    ...session,
    post: (value: unknown) => {
      const message = value as Record<string, unknown>;

      if (message.__atomicChanged || message.type === 'resource-notification') {
        const resource = message.resource as { subject: string } | undefined;
        session.post({
          type: 'atomic.view.change',
          version: 1,
          subject: message.__atomicChanged ?? resource?.subject,
          ...(resource ? { resource } : {}),
        });

        return;
      }

      let result = 'result' in message ? message.result : message.data;

      if (
        result &&
        typeof result === 'object' &&
        'propVals' in result &&
        'subject' in result
      ) {
        result = {
          subject: result.subject,
          props: result.propVals,
          title: 'title' in result ? result.title : result.subject,
          loading: false,
        };
      }

      const error =
        message.error === undefined
          ? undefined
          : String(message.message ?? message.error);
      session.post({
        type: 'atomic.view.response',
        version: 1,
        id,
        ...(error === undefined ? { result } : { error }),
      });
    },
  };
}
