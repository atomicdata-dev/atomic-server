import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
  type KeyboardEvent,
  type MouseEvent,
} from 'react';
import { useCombobox, useSelect } from 'downshift';
import { optionText, type FieldOption } from './types.js';

/** Above this many options the menu grows a filter box. Below it, scanning
 * the list is faster than typing, and downshift's built-in typeahead already
 * covers "jump to the option starting with r". */
const SEARCH_THRESHOLD = 8;

/** Room the menu needs below the trigger before it flips above it. Matches
 * `max-height` on `.atomic-form-combobox-menu` plus the filter box. */
const MENU_HEIGHT = 260;

type Variant = 'single' | 'multi';

/** The shape both arities share. `selected` is a list either way — a
 * single-select's is empty or one long — so the trigger and the menu read the
 * current answer without branching on the variant. */
interface PickerProps {
  variant: Variant;
  options: FieldOption[];
  selected: FieldOption[];
  /** Applies one pick from the menu. */
  onPick: (option: FieldOption) => void;
  /** Empties the field: the trigger's ✕ on a single-select, a chip's ✕ on a
   * multi-select (which passes the option to drop). */
  onRemove: (option?: FieldOption) => void;
  inputId: string;
  labelId: string;
  placeholder?: string;
}

const DEFAULT_PLACEHOLDER: Record<Variant, string> = {
  single: 'Choose an option…',
  multi: 'Choose one or more…',
};

/** Flips the menu above the trigger when the trigger sits too close to the
 * bottom of the window — forms are long, and the last question is routinely
 * the one with the most options. */
function useMenuPlacement(isOpen: boolean): {
  wrapperRef: React.RefObject<HTMLDivElement | null>;
  dropUp: boolean;
} {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [dropUp, setDropUp] = useState(false);

  useEffect(() => {
    if (!isOpen || !wrapperRef.current) return;

    const { bottom, top } = wrapperRef.current.getBoundingClientRect();
    setDropUp(bottom + MENU_HEIGHT > window.innerHeight && top > MENU_HEIGHT);
  }, [isOpen]);

  return { wrapperRef, dropUp };
}

/** Stops a ✕ inside the trigger from also toggling the menu, and keeps focus
 * where it is — downshift closes the menu when focus leaves the control, so
 * without this, clearing an answer would shut an open menu. */
function useTriggerButtonHandlers(): {
  onMouseDown: (e: MouseEvent) => void;
  onKeyDown: (e: KeyboardEvent) => void;
} {
  return {
    onMouseDown: (e: MouseEvent) => {
      e.stopPropagation();
      // Suppressing the default mousedown leaves focus put; the click still
      // fires.
      e.preventDefault();
    },
    onKeyDown: (e: KeyboardEvent) => e.stopPropagation(),
  };
}

interface TriggerProps extends Pick<PickerProps, 'variant' | 'placeholder'> {
  selected: FieldOption[];
  isOpen: boolean;
  onRemove: (option?: FieldOption) => void;
  /** Spread from `getToggleButtonProps()`. */
  buttonProps: Record<string, unknown>;
}

/**
 * The always-visible part, shared by both arities: a multi-select shows its
 * answer as removable chips, a single-select as the bare label plus a ✕ to
 * empty it again (which is what the native `<select>`'s blank first option
 * used to be for).
 *
 * A `<div role='button'>` rather than a `<button>`: the ✕s are buttons, and a
 * button inside a button is invalid HTML.
 */
function Trigger({
  variant,
  selected,
  placeholder,
  isOpen,
  onRemove,
  buttonProps,
}: TriggerProps): JSX.Element {
  const buttonHandlers = useTriggerButtonHandlers();

  const clearButton = (option: FieldOption | undefined, label: string) => (
    <button
      type='button'
      tabIndex={-1}
      aria-label={label}
      {...buttonHandlers}
      onClick={e => {
        e.stopPropagation();
        onRemove(option);
      }}
    >
      <span aria-hidden='true'>✕</span>
    </button>
  );

  return (
    <div
      className={`atomic-form-input atomic-form-combobox-trigger${
        isOpen ? ' atomic-form-combobox-trigger-open' : ''
      }`}
      role='button'
      {...buttonProps}
    >
      <span className='atomic-form-combobox-answer'>
        {selected.length === 0 ? (
          <span className='atomic-form-combobox-placeholder'>
            {placeholder ?? DEFAULT_PLACEHOLDER[variant]}
          </span>
        ) : variant === 'multi' ? (
          selected.map(option => (
            <span className='atomic-form-combobox-chip' key={option.value}>
              {optionText(option)}
              {clearButton(option, `Remove ${option.label}`)}
            </span>
          ))
        ) : (
          <>
            <span className='atomic-form-combobox-value'>
              {optionText(selected[0])}
            </span>
            {clearButton(undefined, 'Clear selection')}
          </>
        )}
      </span>
      <span className='atomic-form-combobox-arrow' aria-hidden='true' />
    </div>
  );
}

/** Downshift puts the *highlight* in `aria-selected`, which here has to mean
 * "chosen" instead — the highlight already travels over
 * `aria-activedescendant`. Overriding it after the spread rather than in the
 * JSX keeps `jsx-a11y` from reading `role='option'` on the `<li>` as a
 * hand-written non-interactive-element-with-interactive-role; downshift sets
 * that same role at runtime either way.
 */
function optionProps(
  fromDownshift: Record<string, unknown>,
  isSelected: boolean,
): Record<string, unknown> {
  return { ...fromDownshift, role: 'option', 'aria-selected': isSelected };
}

interface MenuItemsProps {
  variant: Variant;
  items: FieldOption[];
  selected: FieldOption[];
  highlightedIndex: number;
  getItemProps: (options: {
    item: FieldOption;
    index: number;
  }) => Record<string, unknown>;
}

/**
 * The option rows. A multi-select draws a checkbox per row because several
 * can be on at once; a single-select has exactly one current answer and marks
 * it by styling the row instead — a checkbox there would suggest the rows
 * toggle independently.
 */
function MenuItems({
  variant,
  items,
  selected,
  highlightedIndex,
  getItemProps,
}: MenuItemsProps): JSX.Element {
  if (items.length === 0) {
    return <li className='atomic-form-combobox-empty'>No matches</li>;
  }

  return (
    <>
      {items.map((item, index) => {
        const isSelected = selected.some(o => o.value === item.value);

        return (
          <li
            className='atomic-form-combobox-option'
            key={item.value}
            data-highlighted={index === highlightedIndex || undefined}
            data-current={(variant === 'single' && isSelected) || undefined}
            {...optionProps(getItemProps({ item, index }), isSelected)}
          >
            {variant === 'multi' && (
              // Purely decorative: the row itself carries `aria-selected`, and
              // a real checkbox here would be a second tab stop inside the
              // listbox.
              <span
                className='atomic-form-combobox-check'
                data-checked={isSelected || undefined}
                aria-hidden='true'
              />
            )}
            <span>{optionText(item)}</span>
          </li>
        );
      })}
    </>
  );
}

interface PanelProps {
  dropUp: boolean;
  isOpen: boolean;
  /** Rendered above the list on the searchable variant. */
  filter?: JSX.Element;
  menuProps: Record<string, unknown>;
  children: JSX.Element | false;
}

/** The popover: an optional filter box over the listbox. */
function Panel({
  dropUp,
  isOpen,
  filter,
  menuProps,
  children,
}: PanelProps): JSX.Element {
  return (
    <div
      className={`atomic-form-combobox-panel${
        dropUp ? ' atomic-form-combobox-panel-up' : ''
      }`}
      hidden={!isOpen}
    >
      {filter}
      <ul className='atomic-form-combobox-menu' {...menuProps}>
        {children}
      </ul>
    </div>
  );
}

/** Short option lists: no filter box, downshift's typeahead instead. */
function PlainPicker({
  variant,
  options,
  selected,
  onPick,
  onRemove,
  inputId,
  labelId,
  placeholder,
}: PickerProps): JSX.Element {
  // Downshift's hooks hold refs the React Compiler can't see through.
  'use no memo';

  const keepOpen = variant === 'multi';

  const {
    isOpen,
    getToggleButtonProps,
    getMenuProps,
    getItemProps,
    highlightedIndex,
  } = useSelect({
    items: options,
    itemToString: option => (option ? optionText(option) : ''),
    // Selection lives in `selected`; downshift only drives the menu.
    selectedItem: null,
    stateReducer: (state, { changes, type }) => {
      switch (type) {
        case useSelect.stateChangeTypes.ToggleButtonKeyDownEnter:
        case useSelect.stateChangeTypes.ToggleButtonKeyDownSpaceButton:
        case useSelect.stateChangeTypes.ItemClick:
          // On a multi-select, picking an option is not the end of the
          // interaction — hold the menu open and keep the highlight where it
          // was so several options can be ticked in a row. A single-select
          // takes downshift's default and closes.
          return keepOpen
            ? {
                ...changes,
                isOpen: true,
                highlightedIndex: state.highlightedIndex,
              }
            : changes;
        default:
          return changes;
      }
    },
    onStateChange: ({ type, selectedItem: item }) => {
      switch (type) {
        case useSelect.stateChangeTypes.ToggleButtonKeyDownEnter:
        case useSelect.stateChangeTypes.ToggleButtonKeyDownSpaceButton:
        case useSelect.stateChangeTypes.ItemClick:
          if (item) onPick(item);

          break;
        default:
          break;
      }
    },
  });

  const { wrapperRef, dropUp } = useMenuPlacement(isOpen);

  return (
    <div className='atomic-form-combobox' ref={wrapperRef}>
      <Trigger
        variant={variant}
        selected={selected}
        placeholder={placeholder}
        isOpen={isOpen}
        onRemove={onRemove}
        buttonProps={getToggleButtonProps({
          id: inputId,
          'aria-labelledby': `${labelId} ${inputId}`,
        })}
      />
      <Panel
        dropUp={dropUp}
        isOpen={isOpen}
        menuProps={getMenuProps({ 'aria-multiselectable': keepOpen })}
      >
        {isOpen && (
          <MenuItems
            variant={variant}
            items={options}
            selected={selected}
            highlightedIndex={highlightedIndex}
            getItemProps={getItemProps}
          />
        )}
      </Panel>
    </div>
  );
}

/** Long option lists: the menu opens with a filter box focused. */
function SearchablePicker({
  variant,
  options,
  selected,
  onPick,
  onRemove,
  inputId,
  labelId,
  placeholder,
}: PickerProps): JSX.Element {
  // Downshift's hooks hold refs the React Compiler can't see through.
  'use no memo';

  const keepOpen = variant === 'multi';
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const items = useMemo(() => {
    // Deliberately a plain substring match, not fuzzy: the options are the
    // form author's own words, so typing part of one should turn up exactly
    // the entries containing it.
    const needle = query.trim().toLowerCase();

    if (!needle) return options;

    return options.filter(option =>
      optionText(option).toLowerCase().includes(needle),
    );
  }, [options, query]);

  const {
    isOpen,
    getToggleButtonProps,
    getInputProps,
    getMenuProps,
    getItemProps,
    highlightedIndex,
  } = useCombobox({
    items,
    itemToString: option => (option ? optionText(option) : ''),
    inputValue: query,
    selectedItem: null,
    onInputValueChange: ({ inputValue }) => setQuery(inputValue ?? ''),
    stateReducer: (state, { changes, type }) => {
      switch (type) {
        case useCombobox.stateChangeTypes.InputKeyDownEnter:
        case useCombobox.stateChangeTypes.ItemClick:
          // Multi-select: stay open, keep the highlight, and keep the query,
          // so ticking two matches of one search does not mean retyping it.
          // Single-select: close, and drop the query rather than let
          // downshift replace it with the picked option's label.
          return keepOpen
            ? {
                ...changes,
                isOpen: true,
                highlightedIndex: state.highlightedIndex,
                inputValue: query,
              }
            : { ...changes, inputValue: '' };
        default:
          return changes;
      }
    },
    onStateChange: ({ type, selectedItem: item }) => {
      switch (type) {
        case useCombobox.stateChangeTypes.InputKeyDownEnter:
        case useCombobox.stateChangeTypes.ItemClick:
          if (item) onPick(item);

          break;
        default:
          break;
      }
    },
  });

  const { wrapperRef, dropUp } = useMenuPlacement(isOpen);

  useEffect(() => {
    if (isOpen) {
      // The filter box is inside the panel, so downshift's own "focus the
      // input" never fires — the trigger, not the input, is what was clicked.
      inputRef.current?.focus();
    } else {
      // A stale query would silently hide options the next time it opens.
      setQuery('');
    }
  }, [isOpen]);

  return (
    <div className='atomic-form-combobox' ref={wrapperRef}>
      <Trigger
        variant={variant}
        selected={selected}
        placeholder={placeholder}
        isOpen={isOpen}
        onRemove={onRemove}
        buttonProps={getToggleButtonProps({
          id: inputId,
          // `getToggleButtonProps` takes the input's place as the tab stop,
          // because the input is only reachable once the menu is open.
          tabIndex: 0,
          'aria-labelledby': `${labelId} ${inputId}`,
        })}
      />
      <Panel
        dropUp={dropUp}
        isOpen={isOpen}
        menuProps={getMenuProps({ 'aria-multiselectable': keepOpen })}
        filter={
          <input
            className='atomic-form-combobox-filter'
            {...getInputProps({
              placeholder: 'Filter options…',
              // Downshift merges this with its own input ref.
              ref: inputRef,
            })}
          />
        }
      >
        {isOpen && (
          <MenuItems
            variant={variant}
            items={items}
            selected={selected}
            highlightedIndex={highlightedIndex}
            getItemProps={getItemProps}
          />
        )}
      </Panel>
    </div>
  );
}

/** Picks the flavour by list length. The two are separate components rather
 * than one branchy hook because the choice between `useSelect` and
 * `useCombobox` cannot be made conditionally. */
function Picker(props: PickerProps): JSX.Element {
  return props.options.length > SEARCH_THRESHOLD ? (
    <SearchablePicker {...props} />
  ) : (
    <PlainPicker {...props} />
  );
}

interface SelectProps<T> {
  options: FieldOption[];
  value: T;
  onChange: (value: T) => void;
  /** Goes on the trigger, so the field's `<label htmlFor>` points at it. */
  inputId: string;
  labelId: string;
  placeholder?: string;
}

/**
 * Single-select combobox. The closed trigger shows the chosen option, and a ✕
 * empties the field — the job the native `<select>`'s blank first option used
 * to do.
 */
export function SingleSelect({
  options,
  value,
  onChange,
  ...rest
}: SelectProps<string | undefined>): JSX.Element {
  // An answer naming an option that no longer exists resolves to nothing, so
  // the field reads as unanswered rather than rendering a bare subject.
  const picked = options.filter(option => option.value === value);

  return (
    <Picker
      variant='single'
      options={options}
      selected={picked}
      onPick={option => onChange(option.value)}
      onRemove={() => onChange(undefined)}
      {...rest}
    />
  );
}

/**
 * Multi-select combobox. The closed trigger renders the chosen options as
 * removable chips, so an answer is readable without opening anything.
 */
export function MultiSelect({
  options,
  value,
  onChange,
  ...rest
}: SelectProps<string[]>): JSX.Element {
  /** Add/remove one option, preserving the order `options` declares them in
   * so the chips don't shuffle around as the visitor toggles them. */
  const toggle = (option: FieldOption) => {
    const next = value.includes(option.value)
      ? value.filter(v => v !== option.value)
      : [...value, option.value];

    onChange(options.filter(o => next.includes(o.value)).map(o => o.value));
  };

  return (
    <Picker
      variant='multi'
      options={options}
      selected={options.filter(o => value.includes(o.value))}
      onPick={toggle}
      onRemove={option => option !== undefined && toggle(option)}
      {...rest}
    />
  );
}
