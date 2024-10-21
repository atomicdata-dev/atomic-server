import type { MenuItem } from '@/ontologies/website';
import { unknownSubject, useResource } from '@tomic/react';
import MenuItemLink from './MenuItemLink';
import styles from './MenuItem.module.css';

const MenuItem = ({ subject }: { subject: string }) => {
  const menuItem = useResource<MenuItem>(subject ?? unknownSubject);

  const currentSubject = '';

  const id = (Math.random().toString(36) + '00000000000000000').slice(2, 10);

  return menuItem.props.subItems && menuItem.props.subItems.length > 0 ? (
    <>
      <button
        className={styles.button}
        popoverTarget={id}
        popoverTargetAction='toggle'
      >
        {menuItem.title}
      </button>

      <div id={id} className={styles.submenu} popover='auto'>
        {menuItem.props.subItems?.map((subItem: string, index: number) => (
          <ul className={styles.ul}>
            <li key={index}>
              <MenuItem subject={subItem} />
            </li>
          </ul>
        ))}
      </div>
    </>
  ) : (
    <MenuItemLink
      resource={menuItem}
      active={menuItem.props.linksTo === currentSubject}
    />
  );
};

export default MenuItem;
