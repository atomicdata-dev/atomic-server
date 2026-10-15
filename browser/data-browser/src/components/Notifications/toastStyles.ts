import { styled } from 'styled-components';

/** The look of a toast that announces a chat message; shared by every toaster. */

export const ToastCard = styled.button`
  display: flex;
  align-items: center;
  gap: 0.6rem;
  max-width: 22rem;
  padding: 0.6rem 0.8rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  box-shadow: ${p => p.theme.boxShadowSoft};
  cursor: pointer;
  text-align: left;
  color: ${p => p.theme.colors.text};
`;

export const ToastBody = styled.span`
  display: flex;
  flex-direction: column;
  min-width: 0;
`;

export const ToastTitle = styled.span`
  font-weight: 600;
  font-size: 0.8rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

export const ToastText = styled.span`
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;
