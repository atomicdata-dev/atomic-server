import React from 'react';
import ReactMarkdown from 'react-markdown';
import { styled } from 'styled-components';
import remarkGFM from 'remark-gfm';
import { Button } from '../Button';
import { truncateMarkdown } from '../../helpers/markdown';

type Props = {
  text: string;
  /**
   * By default, all bottom Markdown elements have some margin (e.g. the last
   * paragraph). If you set noMargin, this is corrected.
   */
  noMargin?: boolean;
  renderGFM?: boolean;
  /**
   * If this is set, and the markdown is more characters than this number, the
   * text will be truncated and a button will be shown
   */
  maxLength?: number;
};

/** Renders a markdown value */
function Markdown({
  text,
  noMargin,
  renderGFM,
  maxLength,
}: Props): JSX.Element | null {
  const [collapsed, setCollapsed] = React.useState(true);

  maxLength = maxLength || 5000;

  if (!text) {
    return null;
  }

  return (
    <MarkdownWrapper noMargin={noMargin}>
      <ReactMarkdown remarkPlugins={renderGFM ? [remarkGFM] : []}>
        {collapsed ? truncateMarkdown(text, maxLength) : text}
      </ReactMarkdown>
      {text.length > maxLength && collapsed && (
        <Button subtle onClick={() => setCollapsed(false)}>
          {'Read more '}
        </Button>
      )}
    </MarkdownWrapper>
  );
}

Markdown.defaultProps = {
  renderGFM: true,
};

interface MarkdownWrapperProps {
  noMargin?: boolean;
}

const MarkdownWrapper = styled.div<MarkdownWrapperProps>`
  /* Corrects the margin added by <p> and other HTML elements */
  margin-bottom: -${p => (p.noMargin ? p.theme.margin : 0)}rem;

  width: 100%;
  overflow-x: hidden;
  img {
    max-width: 100%;
  }

  * {
    white-space: unset;
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

  blockquote {
    margin-inline-start: 0rem;
    padding-inline-start: 1rem;
    border-inline-start: solid 3px ${props => props.theme.colors.bg2};
    color: ${props => props.theme.colors.textLight};
  }

  pre code {
    white-space: pre-wrap;
    padding: 1rem;
    width: 100%;
    border-radius: ${p => p.theme.radius};
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
`;

export default Markdown;
