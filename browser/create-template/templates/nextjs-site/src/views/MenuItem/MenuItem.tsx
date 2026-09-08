'use client';

import type { MenuItem } from '@/ontologies/website';
import MenuItemLink from './MenuItemLink';
import styles from './MenuItem.module.css';
import { useResource } from '@tomic/react';
import { useCurrentSubject } from '@/app/context/CurrentSubjectProvider';
import { useId, useRef, useState } from 'react';

export interface MenuItemSnapshot {
  subject: string;
  title: string;
  href: string;
  linksTo?: string;
  subItems: MenuItemSnapshot[];
}

const MenuItem = ({
  subject,
  initial,
}: {
  subject: string;
  initial?: MenuItemSnapshot;
}) => {
  const menuItem = useResource<MenuItem>(subject);
  const { currentSubject } = useCurrentSubject();
  const title = menuItem.loading ? (initial?.title ?? '') : menuItem.title;
  const subItems = menuItem.loading
    ? (initial?.subItems.map(item => item.subject) ?? [])
    : (menuItem.props.subItems ?? []);
  const id = useId();
  const anchorName = cssEscape(`--menuItem-${id}`);
  const popover = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const [submenuPosition, setSubmenuPosition] = useState({
    top: '0px',
    left: '0px',
  });

  const calcPopoverPosition = () => {
    if (!button.current || !popover.current) return;

    if (
      typeof CSS !== 'undefined' &&
      CSS.supports('anchor-name', '--something')
    ) {
      return;
    }

    const rect = button.current.getBoundingClientRect();

    const newSubmenuPosition = { ...submenuPosition };

    newSubmenuPosition.top = `calc(${rect.top}px + 2rem)`;
    newSubmenuPosition.left = `calc(${rect.left}px - (var(--menu-width) / 2 - ${
      rect.width / 2
    }px))`;

    setSubmenuPosition(newSubmenuPosition);
  };

  const closePopover = () => {
    popover.current?.hidePopover();
  };

  const onFocusOut = (event: React.FocusEvent<HTMLDivElement>) => {
    if (
      !event.relatedTarget ||
      !event.currentTarget.contains(event.relatedTarget)
    ) {
      closePopover();
    }
  };

  return subItems.length > 0 ? (
    <>
      <button
        className={styles.button}
        popoverTarget={id}
        popoverTargetAction='toggle'
        onClick={calcPopoverPosition}
        ref={button}
        style={{ '--anchor-name': anchorName } as React.CSSProperties}
      >
        {title}
      </button>

      <div
        id={id}
        className={styles.submenu}
        popover='auto'
        ref={popover}
        onBlur={onFocusOut}
        style={
          {
            '--top': submenuPosition.top,
            '--left': submenuPosition.left,
            '--anchor-name': anchorName,
          } as React.CSSProperties
        }
      >
        <ul className={styles.ul}>
          {subItems.map((subItem: string) => (
            <li key={subItem}>
              <MenuItem
                subject={subItem}
                initial={initial?.subItems.find(
                  item => item.subject === subItem,
                )}
              />
            </li>
          ))}
        </ul>
      </div>
    </>
  ) : (
    <MenuItemLink
      resource={menuItem}
      initial={initial}
      active={menuItem.props.linksTo === currentSubject}
    />
  );
};

const cssEscape = (value: string) => {
  if (typeof CSS !== 'undefined' && CSS.escape) {
    return CSS.escape(value);
  }

  return value.replace(/([!"#$%&'()*+,.\/:;<=>?@[\\\]^`{|}~])/g, '\\$1');
};

export default MenuItem;
