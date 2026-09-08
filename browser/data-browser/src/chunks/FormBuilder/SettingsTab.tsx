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
import { Checkbox, CheckboxLabel } from '@components/forms/Checkbox';
import { FilePicker } from '@components/forms/FilePicker/FilePicker';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Button } from '@components/Button';
import { IconButton } from '@components/IconButton/IconButton';
import { Column, Row } from '@components/Row';
import { Popover } from '@components/Popover';
import { SettingsGroup, SettingsSection } from '@components/Settings';
import { CSSEditor } from '@components/CSSEditor';
import { ExternalLink } from '@components/ExternalLink';
import { useDebounce } from '@helpers/useDebounce';
import { FormAccessSection } from './FormAccessSection';
import { FormScheduleSection } from './FormScheduleSection';

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

const FIELD_SPACINGS: Array<{ value: string; label: string; title: string }> = [
  { value: 'small', label: 'Small', title: 'Compact list of questions' },
  { value: 'large', label: 'Large', title: 'Lots of air between questions' },
];

interface SettingsTabProps {
  resource: Resource;
}

/** Form settings, grouped into collapsible sections like the app settings
 * page: Appearance (cover image, colors, roundness, spacing — previewed 1:1
 * by the Preview dialog and the published runtime via the definition's
 * `styling` object), Form access (public vs invite-only + invite link
 * management), Schedule (the optional open/close window on top of the
 * publish switch) and Custom CSS (collapsed — an escape hatch for what the
 * Appearance controls cannot express). */
export function SettingsTab({ resource }: SettingsTabProps): JSX.Element {
  return (
    <Wrapper>
      <SettingsGroup>
        <SettingsSection label='Form access' initialState>
          <FormAccessSection resource={resource} />
        </SettingsSection>
        <SettingsSection label='Schedule' initialState>
          <FormScheduleSection resource={resource} />
        </SettingsSection>
        <SettingsSection label='Appearance' initialState>
          <AppearanceSettings resource={resource} />
        </SettingsSection>
        <SettingsSection label='Custom CSS'>
          <CustomCssSettings resource={resource} />
        </SettingsSection>
      </SettingsGroup>
    </Wrapper>
  );
}

function AppearanceSettings({ resource }: SettingsTabProps): JSX.Element {
  const coverImageProp = useProperty(forms.properties.coverImage);
  const [coverImage] = useString(resource, forms.properties.coverImage);
  const [position, setPosition] = useString(
    resource,
    forms.properties.imagePosition,
    { commit: true },
  );
  const [styling, setStyling] = useValue(
    resource,
    forms.properties.formStyling,
    { commit: true },
  );

  const stylingObj = parseStylingValue(styling);

  const setStylingKey = (key: string, value: JSONValue | undefined) => {
    const next = { ...stylingObj };

    if (value === undefined) {
      delete next[key];
    } else {
      next[key] = value;
    }

    setStyling(next);
  };

  const showProgressBar = stylingObj.showProgressBar !== false;
  const animatePageTransitions = stylingObj.animatePageTransitions === true;
  const saveDrafts = stylingObj.saveDrafts !== false;

  return (
    <Sections>
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
                subtle={
                  ((stylingObj.roundness as string) ?? 'rounded') !== value
                }
                onClick={() => setStylingKey('roundness', value)}
              >
                {label}
              </Button>
            ))}
          </Row>
        </Field>
      </Section>
      <Section>
        <Field label='Field spacing'>
          <Row gap='0.5rem'>
            {FIELD_SPACINGS.map(({ value, label, title }) => (
              <Button
                key={value}
                subtle={
                  ((stylingObj.fieldSpacing as string) ?? 'small') !== value
                }
                title={title}
                onClick={() => setStylingKey('fieldSpacing', value)}
              >
                {label}
              </Button>
            ))}
          </Row>
        </Field>
      </Section>
      <Section>
        <CheckboxLabel>
          <Checkbox
            checked={showProgressBar}
            onChange={checked =>
              setStylingKey('showProgressBar', checked ? undefined : false)
            }
          />
          Show progress bar on multi-page forms
        </CheckboxLabel>
        <CheckboxLabel>
          <Checkbox
            checked={animatePageTransitions}
            onChange={checked =>
              setStylingKey(
                'animatePageTransitions',
                checked ? true : undefined,
              )
            }
          />
          Animate page transitions
        </CheckboxLabel>
        <Hint>
          Pages zoom out and slide away on Next / Back. Visitors who ask their
          system for reduced motion never see the animation.
        </Hint>
        <CheckboxLabel>
          <Checkbox
            checked={saveDrafts}
            onChange={checked =>
              setStylingKey('saveDrafts', checked ? undefined : false)
            }
          />
          Let visitors resume unfinished forms
        </CheckboxLabel>
        <Hint>
          Half-filled answers are kept in the visitor&apos;s own browser, so
          closing the tab does not lose them, and are cleared once they submit.
          Turn this off for kiosks and other shared devices.
        </Hint>
      </Section>
    </Sections>
  );
}

/** Where the class names custom CSS targets are documented. The stylesheet is
 * the documentation: a hand-written list of hooks here would drift from it
 * within a release, and `.atomic-form-*` is public API precisely because that
 * file says what it is. Pinned to `develop` rather than a tag so it tracks the
 * renderer a running server actually ships. */
const RENDERER_STYLESHEET_URL =
  'https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/form-renderer/src/style.css';

const CSS_PLACEHOLDER = `:scope {
  --atomic-form-accent: #7c3aed;
}

.atomic-form-card {
  border-radius: 24px;
}`;

/** The escape hatch under the Appearance controls: CSS the owner writes, which
 * the renderer injects into the `atomic-form-custom` cascade layer scoped to
 * the form's root element. Because layer order beats specificity, a one-class
 * rule written here wins over anything in the renderer's stylesheet without
 * `!important` — which is the whole point of the feature. */
function CustomCssSettings({ resource }: SettingsTabProps): JSX.Element {
  const [customCss, setCustomCss] = useString(
    resource,
    forms.properties.formCustomCss,
    { commit: true },
  );

  const [draft, setDraft] = useState(customCss ?? '');
  // Every keystroke fires onChange; commit at rest instead of per character.
  const debounced = useDebounce(draft, 500);

  useEffect(() => {
    if (debounced !== (customCss ?? '')) {
      setCustomCss(debounced === '' ? undefined : debounced);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  // Switching builder tabs unmounts this; without a flush, edits made inside
  // the debounce window would be lost. Same shape as ColorSetting's flush.
  const latest = useRef({ draft, customCss, setCustomCss });
  useEffect(() => {
    latest.current = { draft, customCss, setCustomCss };
  });
  useEffect(
    () => () => {
      const pending = latest.current;

      if (pending.draft !== (pending.customCss ?? '')) {
        pending.setCustomCss(pending.draft === '' ? undefined : pending.draft);
      }
    },
    [],
  );

  return (
    <Sections>
      <Section>
        <CSSEditor
          initialValue={customCss ?? ''}
          placeholder={CSS_PLACEHOLDER}
          onChange={setDraft}
        />
        <Hint>
          Applies to the published form and to Preview. It is layered on top of
          the form&apos;s own styles, so you never need <code>!important</code>{' '}
          — a plain <code>.atomic-form-card</code> rule already wins.
        </Hint>
        <Hint>
          Your CSS only sees the form: <code>:scope</code> is its outermost
          element (override the <code>--atomic-form-*</code> variables there),
          and <code>:root</code> and <code>body</code> are out of reach.{' '}
          <code>@import</code> is stripped when the form is served — paste in
          what you need instead.
        </Hint>
        <Hint>
          Every class you can target is in{' '}
          <ExternalLink to={RENDERER_STYLESHEET_URL}>
            the form renderer&apos;s stylesheet
          </ExternalLink>
          .
        </Hint>
      </Section>
    </Sections>
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

const Wrapper = styled.div`
  max-width: 32rem;
`;

const Sections = styled(Column)`
  gap: 1.5rem;
`;

const Section = styled(Column)`
  gap: 0.75rem;
`;

const Hint = styled.p`
  margin: 0;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
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
