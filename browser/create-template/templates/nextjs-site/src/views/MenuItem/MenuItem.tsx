import type { MenuItem } from '@/ontologies/website';
import { unknownSubject, useResource } from '@tomic/react';
import MenuItemLink from './MenuItemLink';
import styles from './MenuItem.module.css';
import { useEffect, useRef } from 'react';

const MenuItem = ({ subject }: { subject: string }) => {
  const menuItem = useResource<MenuItem>(subject ?? unknownSubject);

  const id = (Math.random().toString(36) + '00000000000000000').slice(2, 10);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  return menuItem.props.subItems && menuItem.props.subItems.length > 0 ? (
    <>
      <button
        className={styles.button}
        popovertarget={id}
        popovertargetaction='toggle'
      >
        {menuItem.title}
      </button>

      <div
        id={id}
        className={styles.submenu}
        popover='auto'
        ref={popoverRef}
        tabIndex={-1}
      >
        <ul className={styles.ul}>
          {menuItem.props.subItems?.map((subItem: string, index: number) => (
            <li key={index}>
              <MenuItem subject={subItem} />
            </li>
          ))}
        </ul>
      </div>
    </>
  ) : (
    <MenuItemLink
      resource={menuItem}
      active={menuItem.props.linksTo === subject}
    />
  );
};

export default MenuItem;
