import { useCallback, useState, type JSX, type ReactNode } from 'react';
import Picker from '@emoji-mart/react';
import { styled, useTheme } from 'styled-components';
import * as RadixPopover from '@radix-ui/react-popover';
import { transition } from '../../helpers/transition';
import { Popover } from '../../components/Popover';

export interface EmojiInputProps {
  initialValue?: string;
  onChange: (value: string | undefined) => void;
  /**
   * Custom popover trigger (must be a RadixPopover.Trigger element).
   * Defaults to a small button showing the current emoji.
   */
  Trigger?: ReactNode;
}

const EMOJI_DATA_URL = 'https://cdn.jsdelivr.net/npm/@emoji-mart/data';

let data: Promise<unknown>;

const fetchAndCacheData = async () => {
  if (data) {
    return data;
  }

  const response = await fetch(EMOJI_DATA_URL);
  data = response.json();

  return data;
};

export interface EmojiPickerPanelProps {
  onEmojiSelect: (e: { native: string }) => void;
}

/** The bare emoji-mart picker, for embedding outside the popover (dialogs). */
export function EmojiPickerPanel({
  onEmojiSelect,
}: EmojiPickerPanelProps): JSX.Element {
  return (
    <PickerWrapper>
      <Picker
        autoFocus
        data={fetchAndCacheData}
        onEmojiSelect={onEmojiSelect}
        maxFrequentRows={2}
        dynamicWidth={true}
      />
    </PickerWrapper>
  );
}

export default function EmojiInputASYNC({
  initialValue,
  onChange,
  Trigger,
}: EmojiInputProps): JSX.Element {
  const theme = useTheme();
  const [showPicker, setShowPicker] = useState(false);
  const [emoji, setEmoji] = useState<string | undefined>(initialValue);

  const handleEmojiSelect = useCallback(
    (e: { native: string }) => {
      setEmoji(e.native);
      setShowPicker(false);
      onChange(e.native);
    },
    [onChange],
  );

  return (
    <PickerPopover
      noArrow
      open={showPicker}
      onOpenChange={setShowPicker}
      Trigger={
        Trigger ?? (
          <PickerButton
            onClick={() => setShowPicker(true)}
            title='Pick an emoji'
          >
            {emoji ? <Preview>{emoji}</Preview> : <Placeholder>😎</Placeholder>}
          </PickerButton>
        )
      }
    >
      <PickerWrapper>
        <Picker
          autoFocus
          data={fetchAndCacheData}
          onEmojiSelect={handleEmojiSelect}
          maxFrequentRows={2}
          dynamicWidth={true}
          theme={theme.darkMode ? 'dark' : 'light'}
        />
      </PickerWrapper>
    </PickerPopover>
  );
}

const Preview = styled.span`
  will-change: font-size;
  ${transition('font-size')};
`;

const Placeholder = styled(Preview)`
  opacity: 0.5;
`;

const PickerButton = styled(RadixPopover.Trigger)`
  border: none;
  border-radius: ${({ theme }) => theme.radius};
  width: 2rem;
  height: 2rem;
  background: transparent;
  padding: 0;
  cursor: pointer;
  user-select: none;

  &:hover > ${Preview} {
    font-size: 1.3rem;
  }
`;

const PickerPopover = styled(Popover)`
  top: 200px;
`;

const PickerWrapper = styled.div`
  display: flex;
  flex-direction: column;

  & em-emoji-picker {
    height: 400px;
    width: min(90vw, 20rem);
  }
`;
