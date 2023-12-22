import { properties, useResource, useString, useTitle } from '@tomic/react';
import { useState } from 'react';
import { FaInfo } from 'react-icons/fa';
import { AtomicLink } from '../../AtomicLink';
import { Button } from '../../Button';
import Markdown from '../../datatypes/Markdown';
import { Column, Row } from '../../Row';
import styled from 'styled-components';
import { IconButton, IconButtonVariant } from '../../IconButton/IconButton';

export enum NewFormTitleVariant {
  FullPage,
  Dialog,
}

export interface NewFormTitleProps {
  variant?: NewFormTitleVariant;
  /** The URL of the Class, if available */
  classSubject?: string;
}

const variantHeaderMapping = new Map<
  NewFormTitleVariant,
  keyof JSX.IntrinsicElements
>([
  [NewFormTitleVariant.FullPage, 'h2'],
  [NewFormTitleVariant.Dialog, 'h1'],
]);

export const NewFormTitle: React.FC<NewFormTitleProps> = ({
  classSubject,
  variant,
}) => {
  const klass = useResource(classSubject);
  const [klassTitle] = useTitle(klass);

  const [klassDescription] = useString(klass, properties.description);
  const [showDetails, setShowDetails] = useState(false);

  const headingType = variantHeaderMapping.get(variant!) ?? 'h2';

  return (
    <Column>
      <Row center>
        <Heading as={headingType}>
          new{' '}
          {classSubject ? (
            <AtomicLink subject={classSubject}>{klassTitle}</AtomicLink>
          ) : (
            'Resource'
          )}
        </Heading>
        <IconButton
          variant={IconButtonVariant.Outline}
          onClick={() => setShowDetails(!showDetails)}
          title='Toggle show Class details'
        >
          <FaInfo />
        </IconButton>
      </Row>
      {showDetails && klassDescription && <Markdown text={klassDescription} />}
    </Column>
  );
};

const Heading = styled.h1`
  margin: 0;
`;
