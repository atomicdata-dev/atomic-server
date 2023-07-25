import React, { useEffect } from 'react';
import styled, { keyframes } from 'styled-components';
import { MdSignalWifiOff } from 'react-icons/md';
import { useOnline } from '../hooks/useOnline';
import { lighten } from 'polished';
import toast from 'react-hot-toast';

export function NetworkIndicator() {
  const isOnline = useOnline();

  useEffect(() => {
    if (!isOnline) {
      toast.error('You are offline, changes might not be persisted.');
    }
  }, [isOnline]);

  return (
    <Wrapper shown={!isOnline}>
      <MdSignalWifiOff title='No Internet Connection.' />
    </Wrapper>
  );
}

interface WrapperProps {
  shown: boolean;
}

const pulse = keyframes`
  0% {
    opacity: 1;
    filter: drop-shadow(0 0 5px var(--shadow-color));
  }
  100% {
    opacity: 0.8;
    filter: drop-shadow(0 0 0 var(--shadow-color));
  }
`;

const Wrapper = styled.div<WrapperProps>`
  --shadow-color: ${p => lighten(0.15, p.theme.colors.alert)};
  position: fixed;
  bottom: 1.2rem;
  right: 2rem;
  z-index: ${({ theme }) => theme.zIndex.networkIndicator};
  font-size: 1.5rem;
  color: ${p => p.theme.colors.alert};
  pointer-events: ${p => (p.shown ? 'auto' : 'none')};
  transition: opacity 0.1s ease-in-out;
  opacity: ${p => (p.shown ? 1 : 0)};

  background-color: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.alert};
  border-radius: 50%;
  display: grid;
  place-items: center;
  box-shadow: ${p => p.theme.boxShadowSoft};
  padding: 0.5rem;

  svg {
    animation: ${pulse} 1.5s alternate ease-in-out infinite;
    animation-play-state: ${p => (p.shown ? 'running' : 'paused')};
  }
`;
