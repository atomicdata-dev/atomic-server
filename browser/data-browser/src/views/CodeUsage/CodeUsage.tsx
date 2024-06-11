import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { CodeGenerator, GeneratorLanguage } from './generators/CodeGenerator';
import { HighlightedCodeBlock } from '../../components/HighlightedCodeBlock';
import { TabPanel, Tabs } from '../../components/Tabs';
import { ExternalLink } from '../../components/ExternalLink';
import { Column } from '../../components/Row';
import { VAR_DIALOG_INNER_WIDTH } from '../../components/Dialog';

interface CodeUsageProps {
  generator: CodeGenerator;
  property?: string;
  ts?: boolean;
}

const tabs = [
  { label: 'Vanilla', value: 'vanilla' },
  { label: 'React', value: 'react' },
  { label: 'Svelte', value: 'svelte' },
];

export function CodeUsage({
  generator,
  property,
  ts,
}: CodeUsageProps): React.JSX.Element {
  return (
    <StyledTabs label='syntax' tabs={tabs}>
      <StyledTabPanel value='vanilla'>
        <AsyncCodeDisplay
          codePromise={generator.generateWithOptions({
            language: ts ? GeneratorLanguage.TS : GeneratorLanguage.JS,
            property: property,
          })}
        />
        <span>
          Read the{' '}
          <ExternalLink to='https://docs.atomicdata.dev/js'>
            @tomic/lib docs
          </ExternalLink>{' '}
          for more info.
        </span>
      </StyledTabPanel>
      <StyledTabPanel value='react'>
        <AsyncCodeDisplay
          codePromise={generator.generateWithOptions({
            language: ts ? GeneratorLanguage.TSX : GeneratorLanguage.JSX,
            property: property,
          })}
        />
        <span>
          Read the{' '}
          <ExternalLink to='https://docs.atomicdata.dev/usecases/react'>
            @tomic/react docs
          </ExternalLink>{' '}
          for more info.
        </span>
      </StyledTabPanel>
      <StyledTabPanel value='svelte'>
        <AsyncCodeDisplay
          codePromise={generator.generateWithOptions({
            language: ts
              ? GeneratorLanguage.SvelteTS
              : GeneratorLanguage.Svelte,
            property: property,
          })}
        />
        <span>
          Read the{' '}
          <ExternalLink to='https://docs.atomicdata.dev/svelte'>
            @tomic/svelte docs
          </ExternalLink>{' '}
          for more info.
        </span>
      </StyledTabPanel>
      <span>
        Read more about generating schema&apos;s using{' '}
        <ExternalLink to='https://docs.atomicdata.dev/js-cli'>
          @tomic/cli
        </ExternalLink>
        .
      </span>
    </StyledTabs>
  );
}

interface AsyncCodeDisplayProps {
  codePromise: Promise<string[]>;
}

function AsyncCodeDisplay({ codePromise }: AsyncCodeDisplayProps) {
  const [blocks, setBlocks] = useState<string[]>([]);

  useEffect(() => {
    codePromise.then(setBlocks);
  }, [codePromise]);

  return (
    <Column>
      {blocks.map((c, index) => (
        <StyledHiglightedCodeBlock key={index} code={c} />
      ))}
    </Column>
  );
}

const StyledTabs = styled(Tabs)`
  display: flex;
  flex-direction: column;
  flex: 1;
`;

const StyledTabPanel = styled(TabPanel)`
  flex: 1;
  flex-direction: column;
  max-width: var(${VAR_DIALOG_INNER_WIDTH});
  &[data-state='active'] {
    display: grid;
    grid-template-rows: 1fr 1.5rem;
    height: min-content;
    gap: 1rem;
  }
`;

const StyledHiglightedCodeBlock = styled(HighlightedCodeBlock)`
  max-width: var(${VAR_DIALOG_INNER_WIDTH});
`;
