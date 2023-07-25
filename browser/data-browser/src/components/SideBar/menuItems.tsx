import { FaCog, FaInfo, FaKeyboard, FaUser } from 'react-icons/fa';
import React from 'react';
import { paths } from '../../routes/paths';
import { SideBarMenuItemProps } from './SideBarMenuItem';

export const appMenuItems: SideBarMenuItemProps[] = [
  {
    icon: <FaUser />,
    label: 'User Settings',
    helper: 'See and edit the current Agent / User (u)',
    path: paths.agentSettings,
  },
  {
    icon: <FaCog />,
    label: 'Theme Settings',
    helper: 'Edit the theme, current Agent, and more. (t)',
    path: paths.themeSettings,
  },
  {
    icon: <FaKeyboard />,
    label: 'Keyboard Shortcuts',
    helper: 'View the keyboard shortcuts (?)',
    path: paths.shortcuts,
  },
  {
    icon: <FaInfo />,
    label: 'About',
    helper: 'Welcome page, tells about this app',
    path: paths.about,
  },
];
