import { useEffect } from 'react';
import { useTableEditorContext } from '../TableEditorContext';
import { KeyboardInteraction } from '../helpers/keyboardHandlers';

export interface CellOptions {
  hideActiveIndicator?: boolean;
  disabledKeyboardInteractions?: Set<KeyboardInteraction>;
}
export function useCellOptions(options: CellOptions) {
  const { setIndicatorHidden, setDisabledKeyboardInteractions } =
    useTableEditorContext();

  useEffect(() => {
    if (options.hideActiveIndicator) {
      setIndicatorHidden(true);
    }

    return () => {
      if (options.hideActiveIndicator) {
        setIndicatorHidden(false);
      }
    };
  }, [options.hideActiveIndicator]);

  useEffect(() => {
    if (options.disabledKeyboardInteractions) {
      setDisabledKeyboardInteractions(options.disabledKeyboardInteractions);
    }

    return () => {
      setDisabledKeyboardInteractions(new Set());
    };
  }, [options.disabledKeyboardInteractions]);
}
