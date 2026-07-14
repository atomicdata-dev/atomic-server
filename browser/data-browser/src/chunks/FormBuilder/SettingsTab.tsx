import {
  forms,
  useProperty,
  useString,
  useValue,
  type JSONValue,
  type Resource,
} from '@tomic/react';
import { useEffect, useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import * as RadixPopover from '@radix-ui/react-popover';
import { HexColorPicker } from 'react-colorful';
import { FaXmark } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { FilePicker } from '@components/forms/FilePicker/FilePicker';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Button } from '@components/Button';
import { IconButton } from '@components/IconButton/IconButton';
import { Column, Row } from '@components/Row';
import { Popover } from '@components/Popover';
import { useDebounce } from '@helpers/useDebounce';

const IMAGE_MIMES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
  'image/svg+xml',
]);

const POSITIONS: Array<{ value: string; label: string; title: string }> = [
  { value: 'top', label: 'Top', title: 'Banner above the form' },
  { value: 'left', label: 'Left', title: 'Image pane left of the form' },
  { value: 'right', label: 'Right', title: 'Image pane right of the form' },
  {
    value: 'behind',
    label: 'Behind',
    title: 'Full-page image behind the form card',
  },
  {
    value: 'full',
    label: 'Full',
    title: 'Form rendered directly on the image',
  },
];

const ROUNDNESS_LEVELS: Array<{ value: string; label: string }> = [
  { value: 'sharp', label: 'Sharp' },
  { value: 'rounded', label: 'Rounded' },
  { value: 'round', label: 'Round' },
];

interface SettingsTabProps {
  resource: Resource;
}

/** Styling/theming settings for a Form: cover image (+ position), custom
 * colors and corner roundness. Everything is previewed 1:1 by the Preview
 * dialog and the published runtime via the definition's `styling` object. */
export function SettingsTab({ resource }: SettingsTabProps): JSX.Element {
  const coverImageProp = useProperty(forms.properties.coverImage);
  const [coverImage] = useString(resource, forms.properties.coverImage);
  const [position, setPosition] = useString(
    resource,
    forms.properties.imagePosition,
    { commit: true },
  );
  // validate: false skips the Property-resource fetch on every set — the
  // form-styling Property isn't resolvable from atomicdata.dev yet, and
  // each validation attempt would block the write for up to 10s on a fresh
  // profile. The value shape is owned by this component anyway.
  const [styling, setStyling] = useValue(
    resource,
    forms.properties.formStyling,
    { commit: true, validate: false },
  );

  const stylingObj = parseStylingValue(styling);

  const setStylingKey = (key: string, value: string | undefined) => {
    const next = { ...stylingObj };

    if (value === undefined) {
      delete next[key];
    } else {
      next[key] = value;
    }

    setStyling(next);
  };

  return (
    <Wrapper>
      <Section>
        <Field label='Form image'>
          <FilePicker
            commit
            resource={resource}
            property={coverImageProp}
            allowedMimes={IMAGE_MIMES}
          />
        </Field>
        {coverImage && (
          <Field label='Image position'>
            <Row gap='0.5rem' wrapItems>
              {POSITIONS.map(({ value, label, title }) => (
                <Button
                  key={value}
                  subtle={(position ?? 'top') !== value}
                  title={title}
                  onClick={() => setPosition(value)}
                >
                  {label}
                </Button>
              ))}
            </Row>
          </Field>
        )}
      </Section>
      <Section>
        <ColorSetting
          label='Text color'
          placeholderColor='#1a1a1a'
          value={stylingObj.textColor as string | undefined}
          onChange={value => setStylingKey('textColor', value)}
        />
        <ColorSetting
          label='Main color'
          placeholderColor='#1e43a3'
          value={stylingObj.mainColor as string | undefined}
          onChange={value => setStylingKey('mainColor', value)}
        />
        <ColorSetting
          label='Background color'
          placeholderColor='#ffffff'
          value={stylingObj.backgroundColor as string | undefined}
          onChange={value => setStylingKey('backgroundColor', value)}
        />
      </Section>
      <Section>
        <Field label='Roundness'>
          <Row gap='0.5rem'>
            {ROUNDNESS_LEVELS.map(({ value, label }) => (
              <Button
                key={value}
                subtle={((stylingObj.roundness as string) ?? 'rounded') !== value}
                onClick={() => setStylingKey('roundness', value)}
              >
                {label}
              </Button>
            ))}
          </Row>
        </Field>
      </Section>
    </Wrapper>
  );
}

/** A JSON-datatype value can come back as a raw JSON *string* when the
 * Property resource wasn't resolvable at sign time (no `json` datatype tag
 * gets written into the Loro doc, so rehydration keeps the serialized
 * form). Spreading such a string as if it were an object silently corrupts
 * the next write into indexed characters — parse it defensively instead. */
export function parseStylingValue(
  value: JSONValue | undefined,
): Record<string, JSONValue> {
  let parsed: unknown = value;

  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch {
      return {};
    }
  }

  if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
    return parsed as Record<string, JSONValue>;
  }

  return {};
}

interface ColorSettingProps {
  label: string;
  /** Shown in the picker before a custom color is chosen; not persisted. */
  placeholderColor: string;
  value: string | undefined;
  onChange: (value: string | undefined) => void;
}

function ColorSetting({
  label,
  placeholderColor,
  value,
  onChange,
}: ColorSettingProps): JSX.Element {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(value);
  // The picker fires on every drag frame — debounce before committing.
  const debounced = useDebounce(draft, 200);

  useEffect(() => {
    setDraft(value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  useEffect(() => {
    if (debounced !== value) {
      onChange(debounced);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  // Switching builder tabs unmounts this component; without a flush a color
  // picked within the debounce window would be silently dropped. The ref is
  // written in an effect (not during render) so the React Compiler doesn't
  // interfere with the mutation.
  const latest = useRef({ draft, value, onChange });
  useEffect(() => {
    latest.current = { draft, value, onChange };
  });
  useEffect(
    () => () => {
      const pending = latest.current;

      if (pending.draft !== pending.value) {
        pending.onChange(pending.draft);
      }
    },
    [],
  );

  return (
    <Field label={label}>
      <Row gap='0.5rem' center>
        <Popover
          open={open}
          onOpenChange={setOpen}
          Trigger={
            <SwatchTrigger title={`Pick ${label.toLowerCase()}`}>
              <Swatch $color={draft ?? placeholderColor} $unset={!draft} />
              <SwatchLabel>{draft ?? 'Default'}</SwatchLabel>
            </SwatchTrigger>
          }
        >
          <PickerPanel gap='0.75rem'>
            <HexColorPicker
              color={draft ?? placeholderColor}
              onChange={setDraft}
            />
            <InputWrapper>
              <InputStyled
                value={draft ?? ''}
                placeholder={placeholderColor}
                onChange={e => setDraft(e.target.value || undefined)}
              />
            </InputWrapper>
          </PickerPanel>
        </Popover>
        {draft && (
          <IconButton title='Reset' onClick={() => setDraft(undefined)}>
            <FaXmark />
          </IconButton>
        )}
      </Row>
    </Field>
  );
}

const Wrapper = styled(Column)`
  max-width: 32rem;
  gap: 1.5rem;
`;

const Section = styled(Column)`
  gap: 0.75rem;
`;

const SwatchTrigger = styled(RadixPopover.Trigger)`
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  height: 2rem;
  padding: 0 0.6rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  cursor: pointer;

  &:hover {
    border-color: ${p => p.theme.colors.main};
  }
`;

const Swatch = styled.span<{ $color: string; $unset: boolean }>`
  width: 1.1rem;
  height: 1.1rem;
  border-radius: 0.25rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  background-color: ${p => p.$color};
  opacity: ${p => (p.$unset ? 0.4 : 1)};
`;

const SwatchLabel = styled.span`
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

const PickerPanel = styled(Column)`
  padding: ${p => p.theme.size()};
`;
