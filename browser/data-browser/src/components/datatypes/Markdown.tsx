import ReactMarkdown, { Components, defaultUrlTransform } from 'react-markdown';
import { styled } from 'styled-components';
import remarkGFM from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import remarkMath from 'remark-math';
import { Button } from '@components/Button';
import { truncateMarkdown } from '@helpers/markdown';
import { tryExpandRef } from '@tomic/react';
import { FC, useState } from 'react';
import { AtomicLink, AtomicLinkProps } from '@components/AtomicLink';
import { isAtomicIdentifier } from '@tomic/react';
import { remarkMention, Mention } from './markdown/MarkdownMention';
import { addFieldsIf, addIf } from '@helpers/addIf';
import { diffComponents, remarkDiff } from './markdown/MarkdownDiff';
import { useRehypeKatex } from './markdown/useRehypeKatex';

type Props = {
  text: string;
  renderGFM?: boolean;
  /**
   * Treat single newlines inside paragraphs as hard breaks (like GitHub).
   * Use for diff output so line breaks match the source.
   */
  preserveLineBreaks?: boolean;
  /**
   * If this is set, and the markdown is more characters than this number, the
   * text will be truncated and a button will be shown
   */
  maxLength?: number;
  className?: string;
  nestedInLink?: boolean;
  markExternalLinks?: boolean;
};

const disableElementsInLink = ['a'];

const ExternalLinkComponent = ({
  children: linkChildren,
  href: rawHref,
  ...props
}: React.AnchorHTMLAttributes<HTMLAnchorElement>) => {
  // AI messages link resources via short `#refs`; expand to the full subject.
  const href = rawHref ? (tryExpandRef(rawHref) ?? rawHref) : rawHref;

  // Links to atomic subjects navigate in-app; a plain anchor would trigger
  // a full page (re)load. Everything else stays a regular external link.
  if (href && isAtomicIdentifier(href)) {
    return (
      <AtomicLink subject={href} {...(props as AtomicLinkProps)}>
        {linkChildren}
      </AtomicLink>
    );
  }

  return (
    <AtomicLink href={href} {...(props as AtomicLinkProps)}>
      {linkChildren}
    </AtomicLink>
  );
};

/** Renders a markdown value */
const Markdown: FC<Props> = ({
  text,
  renderGFM = true,
  preserveLineBreaks = false,
  maxLength = 5000,
  className,
  nestedInLink = false,
  markExternalLinks = false,
}) => {
  const [collapsed, setCollapsed] = useState(true);
  const rehypeKatex = useRehypeKatex(text);

  if (!text) {
    return null;
  }

  return (
    <MarkdownWrapper className={className}>
      <ReactMarkdown
        remarkPlugins={[
          ...addIf(renderGFM, remarkGFM),
          ...addIf(preserveLineBreaks, remarkBreaks),
          remarkMath,
          remarkMention,
          remarkDiff,
        ]}
        rehypePlugins={rehypeKatex ? [rehypeKatex] : []}
        // The default transform strips unknown protocols, which would turn
        // links to atomic subjects (did:...) into dead anchors.
        urlTransform={url =>
          isAtomicIdentifier(url) ? url : defaultUrlTransform(url)
        }
        disallowedElements={nestedInLink ? disableElementsInLink : undefined}
        components={
          {
            mention: Mention,
            ...addFieldsIf(markExternalLinks, {
              a: ExternalLinkComponent,
            }),
            ...diffComponents,
            // ReactMarkdowns typing only allows existing html elements but our plugin creates a new type. It works fine, the types are just too strict.
          } as unknown as Components
        }
      >
        {collapsed ? truncateMarkdown(text, maxLength) : text}
      </ReactMarkdown>
      {text.length > maxLength && collapsed && (
        <Button subtle onClick={() => setCollapsed(false)}>
          {'Read more '}
        </Button>
      )}
    </MarkdownWrapper>
  );
};

const MarkdownWrapper = styled.div`
  width: 100%;
  overflow-x: hidden;
  img {
    max-width: 100%;
  }

  * {
    white-space: unset;
  }

  ins,
  del {
    white-space: pre-wrap;
  }

  p,
  h1,
  h2,
  h3,
  h4,
  h5,
  h6 {
    margin-bottom: 1.5rem;
  }

  p:only-child {
    margin-bottom: 0;
  }

  blockquote {
    margin-inline-start: 0rem;
    padding-inline-start: 1rem;
    border-inline-start: solid 3px ${props => props.theme.colors.bg2};
    color: ${props => props.theme.colors.textLight};
  }

  code {
    font-family: Monaco, monospace;
    font-size: 0.8em;
  }

  :not(pre) > code {
    background-color: ${props => props.theme.colors.bg1};
    padding: 0rem 0.2rem;
    font-family: Monaco, monospace;
    display: inline-flex;
    white-space: nowrap;
    overflow: auto;
    max-width: 100%;
  }

  pre {
    background-color: ${p => p.theme.colors.bg1};
    padding: 0.5rem ${p => p.theme.margin}rem;
    border-radius: ${p => p.theme.radius};
    white-space: pre;
    overflow-x: auto;
  }

  table {
    margin-bottom: 1.5rem;
    width: 100%;
  }

  table,
  thead,
  tbody,
  th,
  td {
    border-collapse: collapse;
    padding: 0.5rem;

    border: 1px solid ${props => props.theme.colors.bg2};
  }

  a {
    word-break: break-word;
  }

  ins,
  del {
    /* Ensure they don't break lines unless the text does */
    display: inline;
  }
`;

export default Markdown;
