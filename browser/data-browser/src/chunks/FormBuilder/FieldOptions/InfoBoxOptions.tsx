import { core, forms, Resource, useProperty, useString } from '@tomic/react';
import type { JSX } from 'react';
import {
  INFO_BOX_STYLES,
  infoBoxStyle,
  type InfoBoxStyle,
} from '@tomic/form-renderer';
import Field from '@components/forms/Field';
import { BasicSelect } from '@components/forms/BasicSelect';
import InputSwitcher from '@components/forms/InputSwitcher';

/** The style names, capitalized. The stored values stay lowercase. */
const STYLE_LABELS: Record<InfoBoxStyle, string> = {
  info: 'Info',
  note: 'Note',
  tip: 'Tip',
  success: 'Success',
  warning: 'Warning',
  danger: 'Danger',
};

interface InfoBoxOptionsProps {
  field: Resource;
}

/**
 * The whole settings panel for a FormInfoBox: title, body and style. Unlike a
 * question there is no mapped Property behind it, so the title is written
 * straight to `name` rather than through `renameField`.
 */
export function InfoBoxOptions({ field }: InfoBoxOptionsProps): JSX.Element {
  const nameProp = useProperty(core.properties.name);
  const descriptionProp = useProperty(core.properties.description);
  const [style, setStyle] = useString(
    field,
    forms.properties.formInfoBoxStyle,
    { commit: true },
  );

  return (
    <>
      <Field label='Style'>
        <BasicSelect
          data-testid='info-box-style'
          value={infoBoxStyle(style)}
          onChange={e => setStyle(e.target.value)}
        >
          {INFO_BOX_STYLES.map(option => (
            <option key={option} value={option}>
              {STYLE_LABELS[option]}
            </option>
          ))}
        </BasicSelect>
      </Field>
      <Field label='Title'>
        <InputSwitcher commit resource={field} property={nameProp} />
      </Field>
      <Field label='Text' required>
        <InputSwitcher
          commit
          resource={field}
          property={descriptionProp}
          required
        />
      </Field>
    </>
  );
}
