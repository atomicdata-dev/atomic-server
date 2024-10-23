import type { MenuItem } from '@/ontologies/website';
import MenuItemLink from './MenuItemLink';
import styles from './MenuItem.module.css';
import { store } from '@/app/store';
import { unknownSubject } from '@tomic/lib';

const MenuItem = async ({ subject }: { subject: string }) => {
  const menuItem = await store.getResource<MenuItem>(subject ?? unknownSubject);

  return menuItem.props.subItems && menuItem.props.subItems.length > 0 ? (
    <>
      <button
        className={styles.button}
        popoverTarget='popOver'
        popoverTargetAction='toggle'
      >
        {menuItem.title}
      </button>

      <div id={'popOver'} className={styles.submenu} popover='auto'>
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
      // active={menuItem.props.linksTo === currentSubject}
      active={false}
    />
  );
};

export default MenuItem;
