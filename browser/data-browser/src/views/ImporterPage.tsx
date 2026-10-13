import { Resource, useResource, useStore } from '@tomic/react';
import { useCallback, useId, useMemo, useState } from 'react';
import { Button } from '../components/Button.jsx';
import { ContainerNarrow } from '../components/Containers';
import Field from '../components/forms/Field.jsx';
import {
  InputStyled,
  InputWrapper,
  TextAreaStyled,
} from '../components/forms/InputStyles.jsx';
import { styled } from 'styled-components';
import { Column } from '../components/Row';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { Title } from '../components/Title';
import toast from 'react-hot-toast';
import { Main } from '@components/Main';

type ImporterPageProps = {
  resource?: Resource;
};

/** Importer Resource for uploading JSON-AD * */
export function ImporterPage({ resource }: ImporterPageProps) {
  const parentFieldId = useId();
  const [overwriteOutside, setOverwriteOutside] = useState(false);
  const [parent, setParent] = useCurrentSubject();
  const resourceByS = useResource(parent);
  const [isImporting, setIsImporting] = useState(false);
  const [imported, setImported] = useState(false);

  resource = resourceByS || resource;

  const store = useStore();
  const [jsonAd, setJsonAd] = useState('');

  const handleImport = useCallback(async () => {
    try {
      setIsImporting(true);
      setImported(false);
      await store.importJsonAD(jsonAd, {
        overwriteOutside,
        parent: parent!,
      });

      setImported(true);
      setIsImporting(false);
    } catch (e) {
      toast.error(e.message);
      setIsImporting(false);
    }
  }, [parent, jsonAd, overwriteOutside, store]);

  const disableImportButton = useMemo(
    () => !parent || !jsonAd,
    [parent, jsonAd],
  );

  return (
    <Main>
      <ContainerNarrow>
        <Title resource={resource} prefix='Import to' link />
        <p>
          Read more about how importing Atomic Data works{' '}
          <a href='https://docs.atomicdata.dev/create-json-ad.html'>
            in the docs
          </a>
          .
        </p>
        <Column>
          <Field label='JSON-AD'>
            <InputWrapper>
              <TextAreaStyled
                rows={15}
                placeholder='Paste your JSON-AD...'
                value={jsonAd}
                onChange={e => setJsonAd(e.target.value)}
              >
                {jsonAd}
              </TextAreaStyled>
            </InputWrapper>
          </Field>
          <Header>Options</Header>
          <Group>
            <Label>
              <input
                type='checkbox'
                checked={overwriteOutside}
                onChange={e => setOverwriteOutside(e.target.checked)}
              />
              {`Overwrite resources that are outside the scope of the parent. Do this only if you trust the imported data.`}
            </Label>
            <Field
              label='Target parent'
              helper='This URL will be used as the default Parent for imported resources.'
              required
              fieldId={parentFieldId}
            >
              <InputWrapper>
                <InputStyled
                  id={parentFieldId}
                  required
                  placeholder='Enter subject'
                  value={parent}
                  onChange={e => setParent(e.target.value)}
                />
              </InputWrapper>
            </Field>
          </Group>
          <Button
            data-test='import-post'
            disabled={disableImportButton}
            onClick={handleImport}
          >
            {isImporting ? 'Importing...' : 'Import'}
          </Button>
          {imported && <p role='status'>Imported.</p>}
        </Column>
      </ContainerNarrow>
    </Main>
  );
}

const Label = styled.label`
  display: flex;
  gap: 1ch;
  align-items: center;
`;

const Group = styled.div`
  display: flex;
  padding: 1rem;
  flex-direction: column;
  gap: 1rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
`;

const Header = styled.h2`
  font-size: 1.2rem;
`;
