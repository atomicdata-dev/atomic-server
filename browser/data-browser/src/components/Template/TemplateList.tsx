import { TemplateListItem } from './TemplateListItem';
import { styled } from 'styled-components';
import { website } from './templates/website';
import type { Template } from './template';
import { useState } from 'react';
import { ApplyTemplateDialog } from './ApplyTemplateDialog';

const templates: Template[] = [website];

export function TemplateList(): React.JSX.Element {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<Template>();

  return (
    <>
      <List>
        {templates.map(template => (
          <li key={template.id}>
            <TemplateListItem
              id={template.id}
              title={template.title}
              Image={template.Image}
              onClick={id => {
                setSelectedTemplate(templates.find(t => t.id === id));
                setDialogOpen(true);
              }}
            />
          </li>
        ))}
      </List>
      <ApplyTemplateDialog
        template={selectedTemplate}
        open={dialogOpen}
        bindOpen={setDialogOpen}
      />
    </>
  );
}

const List = styled.ul`
  li {
    list-style: none;
    padding: 0;
    margin: 0;
  }
`;
