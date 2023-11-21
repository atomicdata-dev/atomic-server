import { core, useCanWrite, useProperty, useResource } from '@tomic/react';

import { styled } from 'styled-components';
import InputSwitcher from '../../../components/forms/InputSwitcher';
import { Row } from '../../../components/Row';
import InputString from '../../../components/forms/InputString';
import { PropertyDatatypePicker } from '../PropertyDatatypePicker';
import { IconButton } from '../../../components/IconButton/IconButton';
import { FaSlidersH, FaTimes } from 'react-icons/fa';
import { useDialog } from '../../../components/Dialog';
import { PropertyWriteDialog } from './PropertyWriteDialog';
import { useOntologyContext } from '../OntologyContext';
import { ErrorLook } from '../../../components/ErrorLook';
import { Button } from '../../../components/Button';

interface PropertyLineWriteProps {
  subject: string;
  onRemove: (subject: string) => void;
}

export function PropertyLineWrite({
  subject,
  onRemove,
}: PropertyLineWriteProps): JSX.Element {
  const resource = useResource(subject);
  const shortnameProp = useProperty(core.properties.shortname);
  const descriptionProp = useProperty(core.properties.description);
  const [dialogProps, show, hide] = useDialog();
  const [canEdit] = useCanWrite(resource);

  const { hasProperty } = useOntologyContext();

  const disabled = !canEdit || !hasProperty(subject);

  if (resource.error) {
    return (
      <ListItem>
        <Row center justify='space-between'>
          <StyledErrorLook>
            This property does not exist anymore ({subject})
          </StyledErrorLook>
          <Button alert onClick={() => onRemove(subject)}>
            Remove
          </Button>
        </Row>
      </ListItem>
    );
  }

  return (
    <ListItem>
      <Row center wrapItems>
        <InputSwitcher
          commit
          required
          disabled={disabled}
          resource={resource}
          property={shortnameProp}
        />
        <InputString
          commit
          required
          disabled={disabled}
          resource={resource}
          property={descriptionProp}
        />
        <PropertyDatatypePicker disabled={disabled} resource={resource} />
        <IconButton
          title={`Configure ${resource.title}`}
          color='textLight'
          onClick={show}
        >
          <FaSlidersH />
        </IconButton>
        <IconButton
          title='remove'
          color='textLight'
          onClick={() => onRemove(subject)}
        >
          <FaTimes />
        </IconButton>
      </Row>
      <PropertyWriteDialog resource={resource} {...dialogProps} close={hide} />
    </ListItem>
  );
}

const ListItem = styled.li`
  margin-left: 0px;
  list-style: none;
`;

const StyledErrorLook = styled(ErrorLook)`
  max-lines: 2;
  overflow: hidden;
  flex: 1;
`;
