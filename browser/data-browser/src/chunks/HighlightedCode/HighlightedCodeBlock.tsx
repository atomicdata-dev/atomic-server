import { useEffect, useRef, useState } from 'react';
import { styled } from 'styled-components';
import Prism from 'prismjs';
import { ScrollArea } from '@radix-ui/react-scroll-area';
import {
  IconButton,
  IconButtonVariant,
} from '../../components/IconButton/IconButton';
import { FaCheck, FaCopy } from 'react-icons/fa6';

export interface HiglightedCodeBlockProps {
  code: string;
  className?: string;
}

/** Codeblock with sytax hightlighting for typescript code.
 * Do not import this component directly, use {@link HighlightedCodeBlock} instead.
 */
export default function AsyncHighlightedCodeBlock({
  code,
  className,
}: React.PropsWithChildren<HiglightedCodeBlockProps>): React.JSX.Element {
  const [copied, setIsCopied] = useState(false);

  const ref = useRef<HTMLElement>(null);

  const copyToClipboard = () => {
    setIsCopied(true);
    navigator.clipboard.writeText(code);
  };

  useEffect(() => {
    if (!ref.current) return;
    setTimeout(() => Prism.highlightElement(ref.current!), 0);
  }, [code]);

  useEffect(() => {
    if (copied) {
      const timeout = setTimeout(() => setIsCopied(false), 2000);

      return () => clearTimeout(timeout);
    }
  }, [copied]);

  return (
    <Wrapper>
      <StyledScrollArea type='hover' className={className}>
        <StyledPre>
          <code ref={ref} className='language-typescript'>
            {code}
          </code>
        </StyledPre>
      </StyledScrollArea>
      <CopyButton
        title='Copy code'
        variant={IconButtonVariant.Fill}
        color='textLight'
        size='1.2em'
        onClick={copyToClipboard}
      >
        {copied ? <FaCheck /> : <FaCopy />}
      </CopyButton>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  position: relative;
`;

// We have to use a && selector to increase the specificity because prismjs styles have a high specificity by default.
const StyledPre = styled.pre`
  && {
    font-size: 0.85rem;
    line-height: 1.8em;
    margin: 0;
    padding: 1rem;
    overflow: visible;
    height: min-content;
    background-color: ${p => p.theme.colors.bg1};
    code[class*='language-'],
    &[class*='language-'] {
      color: ${p => p.theme.colors.text};
      text-shadow: none;
    }
    & .operator {
      background-color: ${p => p.theme.colors.bg1};
    }
  }
`;

const StyledScrollArea = styled(ScrollArea)`
  filter: ${p => (p.theme.darkMode ? 'brightness(1.5)' : 'none')};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  overflow: auto;
`;

const CopyButton = styled(IconButton)`
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
`;
