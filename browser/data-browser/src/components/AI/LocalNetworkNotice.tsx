import { Button } from '../Button';
import { Column } from '../Row';
import { WarningBlock } from '../WarningBlock';
import {
  useLocalNetworkBlocked,
  useLocalNetworkExplained,
} from '@helpers/localNetworkAccess';

/** Explains the browser's local network prompt before we trigger it. */
export function LocalNetworkNotice({ url }: { url: string | undefined }) {
  const { markExplained } = useLocalNetworkExplained();

  if (!useLocalNetworkBlocked(url)) return null;

  return (
    <WarningBlock>
      <Column gap='0.5rem'>
        <span role='status'>
          Ollama runs on your own computer. Your browser will ask whether this
          site may access other apps and services on this device. That is only
          used to talk to Ollama; nothing else on your network is scanned.
        </span>
        <div>
          <Button subtle onClick={markExplained}>
            Continue
          </Button>
        </div>
      </Column>
    </WarningBlock>
  );
}
