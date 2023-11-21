import { ReactNode } from 'react';
import { styled } from 'styled-components';
import { constructOpenURL, pathToURL } from '../helpers/navigation';
import { FaExternalLinkAlt } from 'react-icons/fa';
import { ErrorLook } from '../components/ErrorLook';
import { isRunningInTauri } from '../helpers/tauri';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';

export interface AtomicLinkProps
  extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  children?: ReactNode;
  /** An http URL to an Atomic Data resource, opened in this app and fetched as JSON-AD */
  subject?: string;
  /** An http URL to some (external) resource, opened in a new tab and fetched as HTML */
  href?: string;
  /** A path string, e.g. /new, opened using the internal router */
  path?: string;
  untabbable?: boolean;
  /** Minimal styling applied */
  clean?: boolean;
  /** Used to extend with styled */
  className?: string;
}

/**
 * Renders a link. Either a subject or a href is required. You can wrap this
 * around other components and pass the `clean` prop to skip styling.
 */
export const AtomicLink = ({
  children,
  clean,
  subject,
  path,
  href,
  untabbable,
  className,
  ...props
}: AtomicLinkProps): JSX.Element => {
  const navigate = useNavigateWithTransition();

  if (!subject && !href && !path) {
    return (
      <ErrorLook>
        No `subject`, `path` or `href` passed to this AtomicLink.
      </ErrorLook>
    );
  }

  let isOnCurrentPage: boolean;

  try {
    isOnCurrentPage = subject
      ? window.location.toString() === constructOpenURL(subject)
      : false;
  } catch (e) {
    return <span>{subject}</span>;
  }

  const handleClick = (e: React.MouseEvent<HTMLElement>) => {
    if (href) {
      // When there is a regular URL, let the browser handle it
      return;
    }

    e.preventDefault();

    if (path) {
      navigate(path);

      return;
    }

    if (subject) {
      if (isOnCurrentPage) {
        return;
      }

      navigate(constructOpenURL(subject));
    }
  };

  const hrefConstructed = href || subject || pathToURL(path!);

  return (
    <LinkView
      clean={clean}
      className={className}
      about={subject}
      onClick={handleClick}
      href={hrefConstructed}
      disabled={isOnCurrentPage}
      tabIndex={isOnCurrentPage || untabbable ? -1 : 0}
      // Tauri always opens `_blank` in new tab, and ignores preventDefault() for some reason.
      // https://github.com/tauri-apps/tauri/issues/1657
      target={isRunningInTauri() && !href ? '' : '_blank'}
      {...props}
    >
      {children}
      {href && !clean && <FaExternalLinkAlt />}
    </LinkView>
  );
};

type LinkViewProps = {
  disabled?: boolean;
  /** Minimal styling applied */
  clean?: boolean;
};

/** Look clickable, should be used for opening things only - not interactions. */
export const LinkView = styled.a<LinkViewProps>`
  color: ${props =>
    props.disabled ? props.theme.colors.text : props.theme.colors.main};
  text-decoration: none;
  cursor: pointer;
  pointer-events: ${props => (props.disabled ? 'none' : 'inherit')};

  &:hover {
    color: ${props => props.theme.colors.mainLight};
    text-decoration: ${p => (p.clean ? 'none' : 'underline')};
  }
  &:active {
    color: ${props => props.theme.colors.mainDark};
  }
`;
