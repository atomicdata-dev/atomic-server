import { Datatype, useResource } from '@tomic/react';
import { useCallback, useContext, useMemo, useState } from 'react';
import { FaChevronCircleDown, FaFile, FaHashtag, FaPlus } from 'react-icons/fa';
import { DIVIDER, DropdownMenu, DropdownItem } from '../../components/Dropdown';
import { buildDefaultTrigger } from '../../components/Dropdown/DefaultTrigger';
import { dataTypeIconMap } from './dataTypeMaps';
import { NewPropertyDialog } from './PropertyForm/NewPropertyDialog';
import { TablePageContext } from './tablePageContext';
import { ExternalPropertyDialog } from './PropertyForm/ExternalPropertyDialog';

const NewColumnTrigger = buildDefaultTrigger(<FaPlus />, 'Add column');

const TextIcon = dataTypeIconMap.get(Datatype.STRING)!;
const NumberIcon = dataTypeIconMap.get(Datatype.INTEGER)!;
const DateIcon = dataTypeIconMap.get(Datatype.DATE)!;
const CheckboxIcon = dataTypeIconMap.get(Datatype.BOOLEAN)!;
const SelectIcon = FaChevronCircleDown;
const FileIcon = FaFile;
const RelationIcon = dataTypeIconMap.get(Datatype.ATOMIC_URL)!;

export function NewColumnButton(): JSX.Element {
  const [showDialog, setShowDialog] = useState(false);
  const [showExternalDialog, setShowExternalDialog] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string>();

  const { tableClassSubject } = useContext(TablePageContext);
  const tableClassResource = useResource(tableClassSubject);

  const openDialog = useCallback(
    (category: string) => () => {
      setSelectedCategory(category);
      setShowDialog(true);
    },
    [],
  );

  const items = useMemo((): DropdownItem[] => {
    return [
      {
        id: 'text',
        label: 'Text',
        onClick: openDialog('text'),
        icon: <TextIcon />,
      },
      {
        id: 'number',
        label: 'Number',
        onClick: openDialog('number'),
        icon: <NumberIcon />,
      },
      {
        id: 'date',
        label: 'Date',
        onClick: openDialog('date'),
        icon: <DateIcon />,
      },
      {
        id: 'checkbox',
        label: 'Checkbox',
        onClick: openDialog('checkbox'),
        icon: <CheckboxIcon />,
      },
      {
        id: 'select',
        label: 'Select',
        onClick: openDialog('select'),
        icon: <SelectIcon />,
      },
      {
        id: 'file',
        label: 'File',
        onClick: openDialog('file'),
        icon: <FileIcon />,
      },
      {
        id: 'relation',
        label: 'Relation',
        onClick: openDialog('relation'),
        icon: <RelationIcon />,
      },
      DIVIDER,
      {
        id: 'external',
        label: 'External Property',
        onClick: () => setShowExternalDialog(true),
        icon: <FaHashtag />,
      },
    ];
  }, []);

  return (
    <>
      <DropdownMenu trigger={NewColumnTrigger} items={items} />
      <NewPropertyDialog
        showDialog={showDialog}
        tableClassResource={tableClassResource}
        selectedCategory={selectedCategory}
        bindShow={setShowDialog}
      />
      <ExternalPropertyDialog
        open={showExternalDialog}
        tableClassResource={tableClassResource}
        bindShow={setShowExternalDialog}
      />
    </>
  );
}
