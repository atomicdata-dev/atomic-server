import { FC, PropsWithChildren } from 'react';
import * as RadixTabs from '@radix-ui/react-tabs';
import { styled } from 'styled-components';
import { transition } from '../helpers/transition';

type TabItem = {
  label: string;
  value: string;
};

interface TabsProps {
  tabs: TabItem[];
  className?: string;
  label: string;
}

export const Tabs: FC<PropsWithChildren<TabsProps>> = ({
  children,
  tabs,
  label,
  className,
}) => {
  return (
    <RadixTabs.Root defaultValue={tabs[0].value} className={className}>
      <TabList aria-label={label}>
        {tabs.map(tab => (
          <TabButton key={tab.value} value={tab.value}>
            {tab.label}
          </TabButton>
        ))}
      </TabList>
      {children}
    </RadixTabs.Root>
  );
};

interface TabPanelProps {
  value: string;
  className?: string;
}

export const TabPanel: FC<PropsWithChildren<TabPanelProps>> = ({
  value,
  className,
  children,
}) => {
  return (
    <RadixTabs.Content className={className} value={value}>
      {children}
    </RadixTabs.Content>
  );
};

const TabList = styled(RadixTabs.List)`
  display: flex;
  justify-content: space-evenly;
  margin-bottom: ${p => p.theme.margin}rem;
`;

const TabButton = styled(RadixTabs.Trigger)`
  background: none;
  border: none;
  color: ${p => p.theme.colors.text};
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  padding: 1rem;
  flex: 1;
  ${transition('background', 'border-bottom')}
  cursor: pointer;
  &:hover,
  &:focus-visible {
    outline: none;
    background: ${p => p.theme.colors.bg1};
  }

  &[data-state='active'] {
    border-bottom: 2px solid ${p => p.theme.colors.main};
  }
`;
