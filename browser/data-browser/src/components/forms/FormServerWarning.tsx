import { useServerConnected } from '../../hooks/useServerConnected';
import { WarningBlock } from '../WarningBlock';

export function FormServerWarning() {
  const serverConnected = useServerConnected();

  if (serverConnected) return null;

  return (
    <WarningBlock>
      <WarningBlock.Title>No server connected</WarningBlock.Title>
      <p>
        You can create and edit this form, but you need to connect to a server
        before you can publish it and receive responses.
      </p>
    </WarningBlock>
  );
}
