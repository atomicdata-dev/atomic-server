import { useEffect, useMemo, useRef, useState, type JSX } from 'react';
import toast from 'react-hot-toast';
import { FaEraser, FaPen, FaTrash } from 'react-icons/fa6';
import { DropdownMenu, type DropdownItem } from '@components/Dropdown';
import { AutoOpenTrigger } from '@components/Dropdown/AutoOpenTrigger';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { Button } from '@components/Button';
import { InputStyled } from '@components/forms/InputStyles';
import type { CellIndex, CellPasteData } from '@chunks/TableEditor';
import type { TableColumn } from './useTableColumns';

interface CellSelectionMenuProps {
  /** What the selection covers. */
  cells: CellIndex<TableColumn>[];
  /** Where the person right-clicked. */
  point: { x: number; y: number };
  onClose: () => void;
  onClear: (cells: CellIndex<TableColumn>[]) => Promise<void>;
  /** Writes text into cells the way pasting does: parsed per column type. */
  onSetValue: (data: CellPasteData<TableColumn>[]) => void;
  onDeleteRows: (rowIndexes: number[]) => Promise<void>;
}

type Step = 'menu' | 'set-value' | 'delete-rows';

/**
 * The menu for right-clicking a multi-cell selection: what you can do to all of
 * it at once. A single cell keeps the resource menu instead.
 */
export function CellSelectionMenu({
  cells,
  point,
  onClose,
  onClear,
  onSetValue,
  onDeleteRows,
}: CellSelectionMenuProps): JSX.Element {
  const [step, setStep] = useState<Step>('menu');
  // The menu reports itself closed when an item is picked too; that must not
  // tear down the dialog the item is about to open.
  const picked = useRef(false);

  const rowIndexes = useMemo(
    () => [...new Set(cells.map(([row]) => row))].sort((a, b) => a - b),
    [cells],
  );
  const rowCount = rowIndexes.length;

  const items = useMemo((): DropdownItem[] => {
    const pick = (next: Step) => () => {
      picked.current = true;
      setStep(next);
    };

    return [
      {
        id: 'clear-values',
        label: cells.length === 1 ? 'Clear value' : 'Clear values',
        icon: <FaEraser />,
        onClick: () => {
          picked.current = true;
          // Closed now, not when the write lands: by then the person may have
          // opened the menu again, and that one must not be closed under them.
          onClose();
          onClear(cells).catch(e => toast.error((e as Error).message));
        },
      },
      {
        id: 'set-value',
        label: 'Set value…',
        icon: <FaPen />,
        onClick: pick('set-value'),
      },
      {
        id: 'delete-rows',
        label: rowCount === 1 ? 'Delete row' : `Delete ${rowCount} rows`,
        icon: <FaTrash />,
        onClick: pick('delete-rows'),
      },
    ];
  }, [cells, rowCount, onClear, onClose]);

  return (
    <>
      {step === 'menu' && (
        <DropdownMenu
          items={items}
          Trigger={AutoOpenTrigger}
          anchorPoint={point}
          bindActive={active => {
            // The menu closes before the picked item's own handler runs, so
            // wait a tick to see whether an item was picked.
            if (!active) {
              setTimeout(() => !picked.current && onClose(), 0);
            }
          }}
        />
      )}
      {step === 'set-value' && (
        <SetValueDialog
          count={cells.length}
          onClose={onClose}
          onSubmit={value =>
            onSetValue(cells.map(index => ({ index, data: value })))
          }
        />
      )}
      {step === 'delete-rows' && (
        <ConfirmationDialog
          show
          title={rowCount === 1 ? 'Delete row' : `Delete ${rowCount} rows`}
          theme={ConfirmationDialogTheme.Alert}
          confirmLabel='Delete'
          bindShow={show => !show && onClose()}
          onConfirm={() => void onDeleteRows(rowIndexes)}
        >
          <p>
            {rowCount === 1
              ? 'Delete the row this selection touches? You can undo it.'
              : `Delete the ${rowCount} rows this selection touches? You can undo it.`}
          </p>
        </ConfirmationDialog>
      )}
    </>
  );
}

function SetValueDialog({
  count,
  onClose,
  onSubmit,
}: {
  count: number;
  onClose: () => void;
  onSubmit: (value: string) => void;
}): JSX.Element {
  const [value, setValue] = useState('');
  const [dialogProps, show, hide] = useDialog({
    bindShow: shown => !shown && onClose(),
  });

  useEffect(() => {
    show();
  }, [show]);

  const submit = () => {
    onSubmit(value);
    hide();
  };

  return (
    <Dialog {...dialogProps}>
      <DialogTitle>
        <h2>{count === 1 ? 'Set value' : `Set ${count} values`}</h2>
      </DialogTitle>
      <DialogContent>
        <InputStyled
          autoFocus
          aria-label='Value'
          placeholder='Value'
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter') {
              e.preventDefault();
              submit();
            }
          }}
        />
      </DialogContent>
      <DialogActions>
        <Button subtle onClick={() => hide()}>
          Cancel
        </Button>
        <Button onClick={submit}>Set</Button>
      </DialogActions>
    </Dialog>
  );
}
