import { urls, useArray, useProperty, useResource } from '@tomic/react';
import { useCallback } from 'react';
import { Card } from '../../../components/Card';
import { styled } from 'styled-components';
import { FaCube } from 'react-icons/fa';
import { Column, Row } from '../../../components/Row';
import { OntologyDescription } from '../OntologyDescription';
import { PropertyLineWrite } from '../Property/PropertyLineWrite';
import InputSwitcher from '../../../components/forms/InputSwitcher';
import ResourceContextMenu, {
  ContextMenuOptions,
} from '../../../components/ResourceContextMenu';
import { toAnchorId } from '../toAnchorId';
import { AddPropertyButton } from './AddPropertyButton';
import { ErrorChipInput } from '../../../components/forms/ErrorChip';
import { useOntologyContext } from '../OntologyContext';

interface ClassCardWriteProps {
  subject: string;
}

const contextOptions = [ContextMenuOptions.Delete, ContextMenuOptions.History];

export function ClassCardWrite({ subject }: ClassCardWriteProps): JSX.Element {
  const resource = useResource(subject);
  const [requires, setRequires] = useArray(resource, urls.properties.requires, {
    commit: true,
  });
  const [recommends, setRecommends] = useArray(
    resource,
    urls.properties.recommends,
    { commit: true },
  );
  const shortnameProp = useProperty(urls.properties.shortname);

  const { removeClass } = useOntologyContext();

  const handleDelete = useCallback(() => {
    removeClass(subject);
  }, [removeClass, subject]);

  const removeProperty = (type: 'requires' | 'recommends', prop: string) => {
    if (type === 'requires') {
      setRequires(requires.filter(s => s !== prop));
    } else {
      setRecommends(recommends.filter(s => s !== prop));
    }
  };

  return (
    <StyledCard data-testid={`class-card-write-${resource.title}`}>
      <Column id={toAnchorId(subject)}>
        <Row center justify='space-between'>
          <TitleWrapper>
            <FaCube />
            <InputSwitcher
              aria-label='Class name'
              commit
              resource={resource}
              property={shortnameProp}
            />
          </TitleWrapper>
          <ResourceContextMenu
            subject={subject}
            showOnly={contextOptions}
            onAfterDelete={handleDelete}
          />
        </Row>
        <OntologyDescription edit resource={resource} />
        <StyledH4>Requires</StyledH4>
        <Column as='ul' gap='0.5rem'>
          {requires.map(s => (
            <PropertyLineWrite
              key={s}
              subject={s}
              onRemove={prop => removeProperty('requires', prop)}
            />
          ))}
          <ButtonWrapper>
            <AddPropertyButton creator={resource} type='required' />
          </ButtonWrapper>
        </Column>
        <StyledH4>Recommends</StyledH4>
        <Column as='ul' gap='0.5rem'>
          {recommends.map(s => (
            <PropertyLineWrite
              key={s}
              subject={s}
              onRemove={prop => removeProperty('recommends', prop)}
            />
          ))}
          <ButtonWrapper>
            <AddPropertyButton creator={resource} type='recommended' />
          </ButtonWrapper>
        </Column>
      </Column>
    </StyledCard>
  );
}

const StyledCard = styled(Card)`
  padding-bottom: ${p => p.theme.margin}rem;
  max-width: 100rem;

  border: ${p =>
    p.theme.darkMode ? `1px solid ${p.theme.colors.bg2}` : 'none'};

  input,
  select {
    height: 2.5rem;
  }

  ${ErrorChipInput} {
    --error-chip-end: 2.5rem;
  }
`;

const StyledH4 = styled.h4`
  margin-bottom: 0px;
`;

const ButtonWrapper = styled.li`
  margin-left: 0px;
  list-style: none;
`;

const TitleWrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 1ch;
  width: min(100%, 50ch);
  svg {
    font-size: 1.5rem;
  }
`;
