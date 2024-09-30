import { useEffect } from 'react';
import { Dialog, DialogContent, DialogTitle, useDialog } from '../../Dialog';
import { OutlinedSection } from '../../OutlinedSection';
import { useServerSearch, core, type Core, useResource } from '@tomic/react';
import { useSettings } from '../../../helpers/AppSettings';
import { Button } from '../../Button';
import { Column, Row } from '../../Row';

export interface ClassSelectorDialogProps {
  show: boolean;
  bindShow: (show: boolean) => void;
  onClassSelect: (classType: string) => void;
}

export function ClassSelectorDialog({
  show,
  bindShow,
  onClassSelect,
}: ClassSelectorDialogProps): JSX.Element {
  const [dialogProps, showDialog, hideDialog] = useDialog({ bindShow });

  const { drive } = useSettings();

  const { results } = useServerSearch('', {
    filters: {
      [core.properties.isA]: core.classes.ontology,
    },
    parents: [drive],
    allowEmptyQuery: true,
    limit: 100,
  });

  const handleClassSelect = (subject: string) => {
    onClassSelect(subject);
    hideDialog(true);
  };

  useEffect(() => {
    if (show) {
      showDialog();
    }
  }, [show]);

  return (
    <Dialog {...dialogProps} width='45rem'>
      <DialogTitle>
        <h1>Select a class</h1>
      </DialogTitle>
      <DialogContent>
        <Column gap='2rem'>
          {results.map(subject => (
            <OntologySection
              subject={subject}
              onClassSelect={handleClassSelect}
              key={subject}
            />
          ))}
        </Column>
      </DialogContent>
    </Dialog>
  );
}

interface OntologySectionProps {
  subject: string;
  onClassSelect: (subject: string) => void;
}

const OntologySection = ({ subject, onClassSelect }: OntologySectionProps) => {
  const resource = useResource<Core.Ontology>(subject);

  return (
    <OutlinedSection title={resource.title}>
      <Row wrapItems>
        {resource.props.classes?.map(s => (
          <ClassButton key={s} subject={s} onClassSelect={onClassSelect} />
        ))}
      </Row>
    </OutlinedSection>
  );
};

const ClassButton = ({ subject, onClassSelect }: OntologySectionProps) => {
  const resource = useResource<Core.Class>(subject);

  return (
    <Button key={subject} onClick={() => onClassSelect(subject)} subtle>
      {resource.title}
    </Button>
  );
};
