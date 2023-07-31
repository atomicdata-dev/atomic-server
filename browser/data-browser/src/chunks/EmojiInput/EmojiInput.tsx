import React, { useCallback, useState } from 'react';
import Picker from '@emoji-mart/react';
import styled from 'styled-components';
import * as RadixPopover from '@radix-ui/react-popover';
import { transition } from '../../helpers/transition';
import { Popover } from '../../components/Popover';

interface EmojiInputProps {
  initialValue?: string;
  onChange: (value: string | undefined) => void;
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

export default function EmojiInput({
  initialValue,
  onChange,
}: EmojiInputProps): JSX.Element {
  const [showPicker, setShowPicker] = useState(false);
  const [emoji, setEmoji] = useState<string | undefined>(initialValue);

  const handleEmojiSelect = useCallback((e: { native: string }) => {
    setEmoji(e.native);
    setShowPicker(false);
    onChange(e.native);
  }, []);

  return (
    <PickerPopover
      noArrow
      open={showPicker}
      onOpenChange={setShowPicker}
      Trigger={
        <PickerButton onClick={() => setShowPicker(true)} title='Pick an emoji'>
          {emoji ? <Preview>{emoji}</Preview> : <Placeholder>😎</Placeholder>}
        </PickerButton>
      }
    >
      <PickerWrapper>
        <Picker
          autoFocus
          data={fetchAndCacheData}
          onEmojiSelect={handleEmojiSelect}
          maxFrequentRows={2}
          dynamicWidth={true}
        />
      </PickerWrapper>
    </PickerPopover>
  );
}

const Preview = styled.span`
  transition: ${transition('font-size')};
`;

const Placeholder = styled(Preview)`
  opacity: 0.5;
`;

const PickerButton = styled(RadixPopover.Trigger)`
  border: none;
  border-radius: ${({ theme }) => theme.radius};
  width: 2rem;
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
  display: contents;

  & em-emoji-picker {
    height: 400px;
    width: min(90vw, 20rem);
  }
`;
