import ReactMarkdown from 'react-markdown';
import { styled } from 'styled-components';
import remarkGFM from 'remark-gfm';
import { Button } from '../Button';
import { truncateMarkdown } from '../../helpers/markdown';
import { FC, useState } from 'react';

type Props = {
  text: string;
  renderGFM?: boolean;
  /**
   * If this is set, and the markdown is more characters than this number, the
   * text will be truncated and a button will be shown
   */
  maxLength?: number;
  className?: string;
};

/** Renders a markdown value */
const Markdown: FC<Props> = ({ text, renderGFM, maxLength, className }) => {
  const [collapsed, setCollapsed] = useState(true);

  maxLength = maxLength || 5000;

  if (!text) {
    return null;
  }

  return (
    <MarkdownWrapper className={className}>
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
};

Markdown.defaultProps = {
  renderGFM: true,
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
`;

export default Markdown;
