import { type JSONValue, type LocalizedText } from '@tomic/react';

import { useSettings } from '../../../helpers/AppSettings';
import { LocalizedTextValue } from '../../../components/LocalizedTextValue';
import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

import { useState, type JSX } from 'react';

/**
 * Edits one language of a LocalizedText map: the split column's fixed
 * language, or the app's content language (shown in the column header chip).
 * Other languages are untouched; full multi-language editing lives in the
 * resource form.
 */
function LocalizedTextCellEdit({
  value,
  onChange,
  languageTag,
}: EditCellProps<JSONValue>): JSX.Element {
  const { contentLanguage } = useSettings();
  const tag = languageTag ?? contentLanguage;
  const localized = value as LocalizedText | undefined;

  // Mirror the value in synchronous local state, like StringCell, so
  // keystrokes aren't reset by the async resource round-trip. A fresh cell
  // mounts per edit session via the `isEditing` toggle.
  const [localValue, setLocalValue] = useState<string>(localized?.[tag] ?? '');

  return (
    <InputBase
      value={localValue}
      autoFocus
      onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
        setLocalValue(e.target.value);

        // Clearing the text removes the language, so the cell goes back to
        // showing the fallback with the missing-translation marker.
        const next = { ...localized };

        if (e.target.value === '') {
          delete next[tag];
        } else {
          next[tag] = e.target.value;
        }

        onChange(next);
      }}
    />
  );
}

function LocalizedTextCellDisplay({
  value,
  languageTag,
}: DisplayCellProps<JSONValue>): JSX.Element {
  const localized = value as LocalizedText | undefined;

  if (languageTag !== undefined) {
    // A split column shows exactly its language; absence is an honest gap
    // (the empty cell IS the missing-translation indicator).
    return <>{localized?.[languageTag] ?? ''}</>;
  }

  return <LocalizedTextValue value={localized} />;
}

export const LocalizedTextCell: CellContainer<JSONValue> = {
  Edit: LocalizedTextCellEdit,
  Display: LocalizedTextCellDisplay,
};
