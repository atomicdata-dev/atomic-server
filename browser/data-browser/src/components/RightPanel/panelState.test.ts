import { describe, expect, it } from 'vitest';
import { AtomicError, ErrorType } from '@tomic/react';
import {
  emptyPanelState,
  updatePanelState,
  type PanelState,
} from './panelState';
import { panelTargetAvailable } from './useContextualPanel';

const meeting: PanelState = {
  scope: 'alice/drive-one',
  activePanel: 'followSession',
  selectedMeeting: 'did:ad:meeting',
};

describe('right panel lifecycle', () => {
  it('starts closed and without a selected meeting', () => {
    expect(emptyPanelState('alice/drive-one')).toEqual({
      scope: 'alice/drive-one',
      activePanel: null,
    });
  });
  it('clears the meeting when another panel opens or it is closed', () => {
    expect(updatePanelState(meeting, meeting.scope, 'comments', true)).toEqual({
      scope: meeting.scope,
      activePanel: 'comments',
      selectedMeeting: undefined,
    });
    expect(
      updatePanelState(meeting, meeting.scope, 'followSession', false)
        .selectedMeeting,
    ).toBeUndefined();
  });
  it('closing an inactive panel does not close the current one', () => {
    expect(updatePanelState(meeting, meeting.scope, 'comments', false)).toEqual(
      meeting,
    );
  });
  it.each(['bob/drive-one', 'alice/drive-two'])(
    'does not carry panel context into %s or accept an old callback',
    scope => {
      const switched = emptyPanelState(scope);
      expect(switched.activePanel).toBeNull();
      expect(switched.selectedMeeting).toBeUndefined();
      expect(
        updatePanelState(switched, meeting.scope, 'followSession', true),
      ).toBe(switched);
      expect(
        updatePanelState(switched, scope, 'followSession', true)
          .selectedMeeting,
      ).toBeUndefined();
    },
  );
  it('toggle operations use the current state', () => {
    const open = updatePanelState(
      emptyPanelState('a'),
      'a',
      'ai',
      value => !value,
    );
    expect(open.activePanel).toBe('ai');
    expect(
      updatePanelState(open, 'a', 'ai', value => !value).activePanel,
    ).toBeNull();
  });
  it('closes targets that disappeared or lost access, without treating offline/loading as deletion', () => {
    expect(panelTargetAvailable()).toBe(false);
    expect(panelTargetAvailable('meeting')).toBe(true);
    for (const type of [ErrorType.NotFound, ErrorType.Unauthorized])
      expect(
        panelTargetAvailable('meeting', new AtomicError('gone', type)),
      ).toBe(false);
    for (const type of [ErrorType.Transport, ErrorType.Server])
      expect(
        panelTargetAvailable('meeting', new AtomicError('retry', type)),
      ).toBe(true);
  });
});
