import { useEffect, useRef } from 'react';
import { dataBrowser, unknownSubject, useResource } from '@tomic/react';
import { openNative } from './hostActions';

/**
 * A chat room opened in the page (a link to one) is shown by the app's native
 * chat screen when it has one: `onOpened` runs once the app has taken over (the
 * page then goes back to where the link was). When the app has no such screen
 * the page keeps drawing the chat room itself.
 */
export function useNativeChatRoom(subject: string, onOpened: () => void): void {
  const resource = useResource(subject || unknownSubject);
  const isChatRoom = resource.hasClasses(dataBrowser.classes.chatroom);
  const title = resource.title;
  const asked = useRef<string | undefined>(undefined);
  const opened = useRef(onOpened);

  opened.current = onOpened;

  useEffect(() => {
    if (!isChatRoom || asked.current === subject) return;
    asked.current = subject;
    void openNative(dataBrowser.classes.chatroom, subject, title).then(
      handled => {
        if (handled) opened.current();
      },
    );
  }, [isChatRoom, subject, title]);
}
