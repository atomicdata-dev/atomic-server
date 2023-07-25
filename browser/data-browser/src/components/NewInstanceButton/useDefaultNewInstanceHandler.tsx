import {
  classes,
  properties,
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
  const [shortname] = useString(classResource, properties.shortname);

  const createResourceAndNavigate = useCreateAndNavigate(klass, parent);

  const onClick = useCallback(async () => {
    try {
      switch (klass) {
        case classes.chatRoom: {
          createResourceAndNavigate('chatRoom', {
            [properties.name]: 'Untitled ChatRoom',
            [properties.isA]: [classes.chatRoom],
          });
          break;
        }

        case classes.document: {
          createResourceAndNavigate('document', {
            [properties.isA]: [classes.document],
            [properties.name]: 'Untitled Document',
          });
          break;
        }

        case classes.folder: {
          createResourceAndNavigate('folder', {
            [properties.isA]: [classes.folder],
            [properties.name]: 'Untitled Folder',
            [properties.displayStyle]: classes.displayStyles.list,
          });
          break;
        }

        case classes.drive: {
          const agent = store.getAgent();

          if (!agent || agent.subject === undefined) {
            throw new Error(
              'No agent set in the Store, required when creating a Drive',
            );
          }

          const newResource = await createResourceAndNavigate(
            'drive',
            {
              [properties.isA]: [classes.drive],
              [properties.write]: [agent.subject],
              [properties.read]: [agent.subject],
            },
            undefined,
            true,
          );

          const agentResource = await store.getResourceAsync(agent.subject);
          agentResource.pushPropVal(
            properties.drives,
            newResource.getSubject(),
          );
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
