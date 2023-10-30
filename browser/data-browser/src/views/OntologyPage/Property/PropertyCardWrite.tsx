import React, { useCallback } from 'react';
import { Card } from '../../../components/Card';
import { urls, useCanWrite, useProperty, useResource } from '@tomic/react';
import { FaHashtag } from 'react-icons/fa';
import { styled } from 'styled-components';
import { Column, Row } from '../../../components/Row';
import { toAnchorId } from '../toAnchorId';
import InputSwitcher from '../../../components/forms/InputSwitcher';
import ResourceContextMenu, {
  ContextMenuOptions,
} from '../../../components/ResourceContextMenu';
import { useOntologyContext } from '../OntologyContext';
import { PropertyFormCommon } from './PropertyFormCommon';

interface PropertyCardWriteProps {
  subject: string;
}

const contextOptions = [ContextMenuOptions.Delete, ContextMenuOptions.History];

export function PropertyCardWrite({
  subject,
}: PropertyCardWriteProps): JSX.Element {
  const resource = useResource(subject);
  const shortnameProp = useProperty(urls.properties.shortname);
  const [canEdit] = useCanWrite(resource);

  const { removeProperty } = useOntologyContext();

  const handleDelete = useCallback(() => {
    removeProperty(subject);
  }, [removeProperty, subject]);

  return (
    <StyledCard id={toAnchorId(subject)}>
      <Column>
        <Row center justify='space-between'>
          <TitleWrapper>
            <FaHashtag />
            <InputSwitcher
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

const StyledCard = styled(Card)`
  padding-bottom: ${p => p.theme.margin}rem;
`;
