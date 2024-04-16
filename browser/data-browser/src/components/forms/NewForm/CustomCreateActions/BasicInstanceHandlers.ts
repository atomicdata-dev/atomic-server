import { dataBrowser, core, classes, server } from '@tomic/react';
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
          [core.properties.name]: 'Untitled Folder',
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

  registerBasicInstanceHandler(
    server.classes.drive,
    async (_parent, createAndNavigate, { store, settings }) => {
      const agent = store.getAgent();

      if (!agent || agent.subject === undefined) {
        throw new Error(
          'No agent set in the Store, required when creating a Drive',
        );
      }

      const newResource = await createAndNavigate(server.classes.drive, {
        [core.properties.write]: [agent.subject],
        [core.properties.read]: [agent.subject],
      });

      // resources created with createAndNavigate have a parent by default which we don't want for drives.
      newResource.remove(core.properties.parent);

      const agentResource = await store.getResource(agent.subject);
      agentResource.push(server.properties.drives, [newResource.subject]);
      agentResource.save();
      settings.setDrive(newResource.subject);
    },
  );
};
