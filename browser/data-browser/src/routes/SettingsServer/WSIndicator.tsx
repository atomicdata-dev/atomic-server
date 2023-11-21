import { useStore } from '@tomic/react';
import { useEffect, useState } from 'react';
import { FaExclamationTriangle, FaSignal } from 'react-icons/fa';
import { styled } from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';

export interface WSIndicatorProps {
  subject: string;
  className?: string;
}

enum ReadyState {
  CONNECTING = WebSocket.CONNECTING,
  OPEN = WebSocket.OPEN,
  CLOSING = WebSocket.CLOSING,
  CLOSED = WebSocket.CLOSED,
}

function getIndicatorState(
  readyState: ReadyState,
): [icon: React.ReactNode, color: string] {
  switch (readyState) {
    case ReadyState.OPEN:
      return [
        <FaSignal
          color='#3AA55D'
          key='connected'
          title='Websocket Connected'
        />,
        'green',
      ];
    case ReadyState.CLOSING:
      return [
        <FaSignal color='orange' key='closing' title='Websocket Closing' />,
        '#FAA81A',
      ];
    case ReadyState.CLOSED:
      return [
        <FaExclamationTriangle
          color='red'
          key='closed'
          title='Websocket Closed'
        />,
        '#ED4245',
      ];
    case ReadyState.CONNECTING:
    default:
      return [
        <FaSignal
          color='gray'
          key='connecting'
          title='Websocket Connecting...'
        />,
        'gray',
      ];
  }
}

/** Shows the status of a WebSocket connection for some resource. */
export function WSIndicator({
  subject,
  className,
}: WSIndicatorProps): JSX.Element {
  const store = useStore();
  const { drive } = useSettings();

  const [websocketReadyState, setWebsocketReadyState] = useState<ReadyState>(
    store.getWebSocketForSubject(subject)?.readyState ?? ReadyState.CONNECTING,
  );

  useEffect(() => {
    const ws = store.getWebSocketForSubject(subject);

    if (!ws) {
      return setWebsocketReadyState(ReadyState.CONNECTING);
    }

    setWebsocketReadyState(ws?.readyState);

    const interval = setInterval(() => {
      if (ws.readyState !== websocketReadyState) {
        setWebsocketReadyState(ws.readyState);
      }
    }, 1000);

    return () => {
      clearInterval(interval);
    };
  }, [drive, store]);

  const [icon, color] = getIndicatorState(websocketReadyState);

  return (
    <IconWrapper color={color} className={className}>
      {icon}
    </IconWrapper>
  );
}

interface ColorProps {
  color: string;
}

const IconWrapper = styled.div<ColorProps>`
  display: contents;
  color: ${p => p.color};
  font-size: 1rem;
`;
