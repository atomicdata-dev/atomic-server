import toast, { ToastBar, Toaster as ReactHotToast } from 'react-hot-toast';
import { FaCopy, FaTimes } from 'react-icons/fa';
import { useTheme } from 'styled-components';
import { zIndex } from '../styling';
import { Row } from './Row';
import { IconButton } from './IconButton/IconButton';

/**
 * Makes themed toast notifications available in the Context. Render this
 * somewhere high up in the app
 */
export function Toaster(): JSX.Element {
  const theme = useTheme();

  return (
    <ReactHotToast
      position='bottom-right'
      toastOptions={{
        style: {
          zIndex: zIndex.toast,
          background: theme.colors.bg,
          color: theme.colors.text,
          wordBreak: 'break-word',
        },
      }}
    >
      {t => (
        <ToastBar
          toast={t}
          style={{
            ...t.style,
            border: `solid 1px ${theme.colors.bg2}`,
            position: 'relative',
            animation: t.visible
              ? 'toast-enter .5s ease'
              : 'toast-exit 1s ease',
          }}
        >
          {({ icon, message }) => (
            <ToastMessage icon={icon} message={message} t={t} />
          )}
        </ToastBar>
      )}
    </ReactHotToast>
  );
}

function ToastMessage({ icon, message, t }) {
  let text = message.props.children;

  function handleCopy() {
    toast.success('Copied error to clipboard');
    navigator.clipboard.writeText(message.props.children);
    toast.dismiss(t.id);
  }

  if (text.length > 100) {
    text = text.substring(0, 100) + '...';
  }

  return (
    <Row gap='1ch' center>
      {icon}
      {text}
      {t.type !== 'loading' && (
        <div
          style={{
            flex: 1,
            flexDirection: 'column',
          }}
        >
          <IconButton title='Clear' onClick={() => toast.dismiss(t.id)}>
            <FaTimes />
          </IconButton>
          {t.type !== 'success' && (
            <IconButton title='Copy' onClick={handleCopy}>
              <FaCopy />
            </IconButton>
          )}
        </div>
      )}
    </Row>
  );
}
