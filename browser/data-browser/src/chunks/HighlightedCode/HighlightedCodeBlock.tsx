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
  language?: string;
}

/** Codeblock with sytax hightlighting for typescript code.
 * Do not import this component directly, use {@link HighlightedCodeBlock} instead.
 */
export default function AsyncHighlightedCodeBlock({
  code,
  className,
  language = 'typescript',
}: React.PropsWithChildren<HiglightedCodeBlockProps>): React.JSX.Element {
  const [copied, setIsCopied] = useState(false);

  const ref = useRef<HTMLElement>(null);

  const copyToClipboard = () => {
    setIsCopied(true);
    navigator.clipboard.writeText(code);
  };

  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const timer = setTimeout(() => Prism.highlightElement(element), 0);

    return () => clearTimeout(timer);
  }, [code, language]);

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
          <code ref={ref} className={`language-${language}`}>
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
      background-color: transparent;
    }
    & .deleted {
      background-color: #ff9f9f;
      color: #4d0000;
    }
    & .inserted {
      background-color: #d4ffd4;
      color: #004d00;
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
