import { styled } from 'styled-components';
import { FeedbackMenuItem } from './SideBar/FeedbackMenuItem';

/** Shared corner placement for onboarding pages and their dialogs. */
export function OnboardingFeedback() {
  return (
    <Corner>
      <FeedbackMenuItem floating />
    </Corner>
  );
}

const Corner = styled.div`
  position: fixed;
  right: max(1rem, env(safe-area-inset-right));
  bottom: max(1rem, env(safe-area-inset-bottom));
  z-index: ${p => p.theme.zIndex.sidebar};
`;
