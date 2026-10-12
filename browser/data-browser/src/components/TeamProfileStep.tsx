import {
  core,
  dataBrowser,
  useResourceSnapshot,
  useStore,
  useString,
} from '@tomic/react';
import { ProfileForm } from './ProfileForm';
import { ResourceGlyph } from './ResourceGlyph';

/** The profile form for an agent that already exists: saves to its resource. */
export function TeamProfileStep({
  subject,
  onContinue,
}: {
  subject: string;
  onContinue: () => void | Promise<void>;
}) {
  const store = useStore();
  const { resource, ready } = useResourceSnapshot(subject);
  const [name] = useString(resource, core.properties.name);

  return (
    <ProfileForm
      // Remount once the profile loads, so the field starts with its name.
      key={ready ? 'ready' : 'loading'}
      initialName={name ?? ''}
      currentAvatar={
        resource.get(dataBrowser.properties.icon) ? (
          <ResourceGlyph resource={resource} />
        ) : undefined
      }
      disabled={!ready}
      error={resource.error}
      onSave={async ({ name: fullName, picture }) => {
        if (!resource.isReady()) return;

        if (picture) {
          const [uploaded] = await store.uploadFiles([picture], subject);
          if (!uploaded)
            throw new Error('Your profile picture could not be uploaded.');
          await resource.set(dataBrowser.properties.icon, uploaded);
        }

        await resource.set(core.properties.name, fullName);
        await resource.save();
        await onContinue();
      }}
    />
  );
}
