import { styled } from 'styled-components';
import * as RadixPopover from '@radix-ui/react-popover';
import { Popover } from '../../../components/Popover';

export const AbsoluteCell = styled.div`
  position: absolute;
  display: flex;
  align-items: center;
  z-index: 10;
  left: 0;
  top: 0;
  background-color: ${p => p.theme.colors.bg};
  box-shadow: ${p => p.theme.boxShadowSoft};
  border: 2px solid ${p => p.theme.colors.main};
  height: fit-content;
  width: 100%;
  padding-inline: var(--table-inner-padding);
  padding-block: 3px;
  min-height: 40px;
`;

export const SearchPopover = styled(Popover)`
  padding: 1rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

export const SearchResultWrapper = styled.div`
  height: min(90vh, 20rem);
  width: min(90vw, 35rem);
  overflow-x: hidden;
  overflow-y: auto;

  ol {
    padding: 0;
    margin: 0;
  }

  li {
    list-style: none;
    &[data-selected='true'] button {
      background: ${p => p.theme.colors.main};
      color: white;

      svg {
        color: white;
      }
    }
  }
`;

export const PopoverTrigger = styled(RadixPopover.Trigger)`
  border: none;
  background: none;
  color: ${p => p.theme.colors.main};
  display: inline-flex;
  gap: 1ch;
  align-items: center;
  user-select: none;
  cursor: pointer;
`;
