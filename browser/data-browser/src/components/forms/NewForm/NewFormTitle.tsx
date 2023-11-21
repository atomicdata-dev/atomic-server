import { properties, useResource, useString, useTitle } from '@tomic/react';
import { useState } from 'react';
import { FaInfo } from 'react-icons/fa';
import { AtomicLink } from '../../AtomicLink';
import { Button } from '../../Button';
import Markdown from '../../datatypes/Markdown';

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

  const HeadingComp = variantHeaderMapping.get(variant!) ?? 'h2';

  return (
    <>
      <HeadingComp>
        new{' '}
        {classSubject ? (
          <AtomicLink subject={classSubject}>{klassTitle}</AtomicLink>
        ) : (
          'Resource'
        )}
        <Button
          onClick={() => setShowDetails(!showDetails)}
          icon
          subtle={!showDetails}
          title='Toggle show Class details'
        >
          <FaInfo />
        </Button>
      </HeadingComp>
      {showDetails && klassDescription && <Markdown text={klassDescription} />}
    </>
  );
};
