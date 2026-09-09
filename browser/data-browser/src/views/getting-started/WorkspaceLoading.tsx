import { Spinner } from '../../components/Spinner';
import { Column } from '../../components/Row';
import { CardSubtitle, CardTitle } from './chrome';

export function WorkspaceLoading({
  stage,
}: {
  stage: 'identity' | 'local' | 'backup' | 'discovery' | 'fetch';
}) {
  return (
    <Column gap='1rem' role='status' aria-live='polite' aria-busy='true'>
      <div style={{ alignSelf: 'center' }}>
        <Spinner size='2.5rem' />
      </div>
      <CardTitle>Opening your workspace</CardTitle>
      <CardSubtitle>
        {stage === 'identity'
          ? 'Your secret was accepted. Preparing this device…'
          : stage === 'local'
            ? 'Checking for your workspace on this device…'
            : stage === 'backup'
              ? 'Checking whether your account has a backup to restore…'
              : stage === 'discovery'
                ? 'Looking for a device that has your workspace…'
                : 'Fetching your workspace to this device…'}
      </CardSubtitle>
      <CardSubtitle>
        This may take a little while. Please keep this window open.
      </CardSubtitle>
    </Column>
  );
}
