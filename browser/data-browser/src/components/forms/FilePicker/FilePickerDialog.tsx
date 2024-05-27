import React, { useEffect, useState } from 'react';
import {
  DIALOG_MEDIA_BREAK_POINT,
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../Dialog';
import { InputStyled, InputWrapper } from '../InputStyles';
import { FaPlus, FaSearch } from 'react-icons/fa';
import { core, server, useServerSearch } from '@tomic/react';
import { styled } from 'styled-components';
import { FilePickerItem } from './FilePickerItem';
import { Button } from '../../Button';
import { Row } from '../../Row';
import { useSettings } from '../../../helpers/AppSettings';
import { useMediaQuery } from '../../../hooks/useMediaQuery';

interface FilePickerProps {
  show: boolean;
  onShowChange?: (show: boolean) => void;
  onResourcePicked: (subject: string) => void;
  onNewFilePicked: (file: File) => void;
  noUpload?: boolean;
  allowedMimes?: Set<string>;
}

export function FilePickerDialog({
  show,
  onShowChange,
  onNewFilePicked,
  onResourcePicked,
  allowedMimes,
  noUpload = false,
}: FilePickerProps): React.JSX.Element {
  const { drive } = useSettings();
  const [dialogProps, showDialog, closeDialog] = useDialog({
    bindShow: onShowChange,
  });

  const isScreenSmall = useMediaQuery(
    `(max-width: ${DIALOG_MEDIA_BREAK_POINT})`,
    false,
  );

  const [query, setQuery] = useState('');

  const { results } = useServerSearch(query, {
    filters: {
      [core.properties.isA]: server.classes.file,
    },
    allowEmptyQuery: true,
    parents: [drive],
  });

  const handleResourcePicked = (subject: string) => {
    onResourcePicked(subject);
    closeDialog(true);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];

    if (file) {
      onNewFilePicked(file);
      closeDialog(true);
    }
  };

  useEffect(() => {
    if (show) {
      showDialog();
      setQuery('');
    }
  }, [show, showDialog]);

  return (
    <Dialog {...dialogProps} width='70rem'>
      {show && (
        <>
          <DialogTitle>
            <Row wrapItems>
              <InputWrapper hasPrefix>
                <FaSearch />
                <InputStyled
                  type='search'
                  placeholder='Search...'
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                />
              </InputWrapper>
              {!noUpload && (
                <StyledLabel>
                  <Button as='div'>
                    <FaPlus aria-hidden /> {isScreenSmall ? '' : 'Upload'}
                  </Button>
                  <input
                    type='file'
                    style={{ display: 'none' }}
                    onChange={handleFileInputChange}
                  />
                </StyledLabel>
              )}
            </Row>
          </DialogTitle>
          <StyledDialogContent>
            {results.map(subject => (
              <FilePickerItem
                allowedMimes={allowedMimes}
                subject={subject}
                key={subject}
                onClick={() => handleResourcePicked(subject)}
              />
            ))}
          </StyledDialogContent>
        </>
      )}
    </Dialog>
  );
}

const StyledDialogContent = styled(DialogContent)`
  padding-top: 1px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(10rem, 1fr));
  gap: ${p => p.theme.margin * 2}rem;
  height: 80dvh;
`;

const StyledLabel = styled.label`
  & div {
    height: 100%;
  }
`;
