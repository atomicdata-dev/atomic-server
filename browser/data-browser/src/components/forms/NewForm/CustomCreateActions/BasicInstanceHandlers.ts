import { dataBrowser, core, classes } from '@tomic/react';
import { registerBasicInstanceHandler } from '../useNewResourceUI';

/**
 * These handlers do not show any UI / inputs when creating new instances.
 * This is where they can have hardcoded default values or custom logic.
 */
export const registerBasicInstanceHandlers = () => {
  registerBasicInstanceHandler(
    dataBrowser.classes.folder,
    async (parent, createAndNavigate) => {
      await createAndNavigate(
        dataBrowser.classes.folder,
        {
          [core.properties.name]: 'untitled-folder',
          [dataBrowser.properties.displayStyle]: classes.displayStyles.list,
        },
        parent,
      );
    },
  );

  registerBasicInstanceHandler(
    dataBrowser.classes.chatroom,
    async (parent, createAndNavigate) => {
      await createAndNavigate(
        dataBrowser.classes.chatroom,
        {
          [core.properties.name]: 'Untitled ChatRoom',
        },
        parent,
      );
    },
  );

  registerBasicInstanceHandler(
    dataBrowser.classes.document,
    async (parent, createAndNavigate) => {
      createAndNavigate(
        dataBrowser.classes.document,
        {
          [core.properties.name]: 'Untitled Document',
        },
        parent,
      );
    },
  );
};
