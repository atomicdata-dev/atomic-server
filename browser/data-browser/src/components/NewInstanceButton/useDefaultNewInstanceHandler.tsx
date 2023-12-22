import {
  classes,
  core,
  dataBrowser,
  server,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSettings } from '../../helpers/AppSettings';
import { newURL } from '../../helpers/navigation';
import { useCreateAndNavigate } from './useCreateAndNavigate';

/**
 * Returns a function that can be used to create a new instance of the given Class.
 * This is the place where you can add custom behavior for certain classes.
 * By default, we're redirected to an empty Form for the new instance.
 * For some Classes, though, we'd rather have some values are pre-filled (e.g. a new ChatRoom with a `new chatroom` title).
 * For others, we want to render a custom form, perhaps with a different layout.
 */
export function useDefaultNewInstanceHandler(klass: string, parent?: string) {
  const store = useStore();
  const { setDrive } = useSettings();
  const navigate = useNavigate();

  const classResource = useResource(klass);
  const [shortname] = useString(classResource, core.properties.shortname);

  const createResourceAndNavigate = useCreateAndNavigate();

  const onClick = useCallback(async () => {
    try {
      switch (klass) {
        case dataBrowser.classes.chatroom: {
          createResourceAndNavigate(
            dataBrowser.classes.chatroom,
            {
              [core.properties.name]: 'Untitled ChatRoom',
            },
            parent,
          );
          break;
        }

        case dataBrowser.classes.document: {
          createResourceAndNavigate(
            dataBrowser.classes.document,
            {
              [core.properties.name]: 'Untitled Document',
            },
            parent,
          );
          break;
        }

        case dataBrowser.classes.folder: {
          createResourceAndNavigate(
            dataBrowser.classes.folder,
            {
              [core.properties.name]: 'Untitled Folder',
              [dataBrowser.properties.displayStyle]: classes.displayStyles.list,
            },
            parent,
          );
          break;
        }

        case server.classes.drive: {
          const agent = store.getAgent();

          if (!agent || agent.subject === undefined) {
            throw new Error(
              'No agent set in the Store, required when creating a Drive',
            );
          }

          const newResource = await createResourceAndNavigate(
            server.classes.drive,
            {
              [core.properties.write]: [agent.subject],
              [core.properties.read]: [agent.subject],
            },
          );

          const agentResource = await store.getResourceAsync(agent.subject);
          agentResource.pushPropVal(server.properties.drives, [
            newResource.getSubject(),
          ]);
          agentResource.save(store);
          setDrive(newResource.getSubject());
          break;
        }

        default: {
          // Opens an `Edit` form with the class and a decent subject name
          navigate(newURL(klass, parent, store.createSubject(shortname)));
        }
      }
    } catch (e) {
      store.notifyError(e);
    }
  }, [klass, store, parent, createResourceAndNavigate]);

  return onClick;
}
