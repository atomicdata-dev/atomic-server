import { useCallback, type JSX } from 'react';
import { core, useCanWrite, useProperty, useResource } from '@tomic/react';
import { FaHashtag } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Column, Row } from '../../../components/Row';
import InputSwitcher from '../../../components/forms/InputSwitcher';
import {
  ContextMenuOptions,
  ResourceContextMenu,
} from '../../../components/ResourceContextMenu';
import { useOntologyContext } from '../OntologyContext';
import { PropertyFormCommon } from './PropertyFormCommon';
import { TargetableCard } from '../TargetableCard';
import { isContentAddressed } from '../../../helpers/propertyIdentity';

interface PropertyCardWriteProps {
  subject: string;
}

export function PropertyCardWrite({
  subject,
}: PropertyCardWriteProps): JSX.Element {
  const contextOptions = [
    ContextMenuOptions.Open,
    ContextMenuOptions.Delete,
    ContextMenuOptions.History,
  ];
  const resource = useResource(subject);
  const shortnameProp = useProperty(core.properties.shortname);
  const canEdit = useCanWrite(resource);

  const { removeProperty } = useOntologyContext();

  const handleDelete = useCallback(() => {
    removeProperty(subject);
  }, [removeProperty, subject]);

  return (
    <StyledCard subject={subject}>
      <Column>
        <Row center justify='space-between'>
          <TitleWrapper>
            <FaHashtag />
            <InputSwitcher
              commit
              // The shortname is part of a content-addressed property's ID.
              disabled={!canEdit || isContentAddressed(subject)}
              resource={resource}
              property={shortnameProp}
            />
          </TitleWrapper>
          <ResourceContextMenu
            external
            subject={subject}
            showOnly={contextOptions}
            onAfterDelete={handleDelete}
          />
        </Row>
        <PropertyFormCommon resource={resource} canEdit={canEdit} />
      </Column>
    </StyledCard>
  );
}

const TitleWrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 1ch;
  margin-bottom: 0px;

  svg {
    font-size: 1.5rem;
  }
`;

const StyledCard = styled(TargetableCard)`
  box-shadow: ${p => p.theme.boxShadow};
  border: ${p =>
    p.theme.darkMode ? `1px solid ${p.theme.colors.bg2}` : 'none'};
  padding-bottom: ${p => p.theme.margin}rem;
`;
