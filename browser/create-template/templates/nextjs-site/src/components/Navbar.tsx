import { useResource } from '@tomic/react';
import Container from './Layout/Container';
import HStack from './Layout/HStack';
import { env } from '@/env';
import { website, Website } from '@/ontologies/website';
import MenuItem from '@/views/MenuItem/MenuItem';
import styles from './Navbar.module.css';
import { store } from '@/app/store';

const Navbar = async () => {
  // const site = useResource<Website>(env.NEXT_PUBLIC_WEBSITE_RESOURCE);
  const site = await store.getResource<Website>(
    env.NEXT_PUBLIC_WEBSITE_RESOURCE,
  );

  return (
    <Container>
      <nav className={styles.nav}>
        <HStack align='center' justify='space-between' wrap>
          <a href='/' className={styles.title}>
            {site.title}
          </a>
          <ul className={styles.ul}>
            {site.props.menuItems?.map((menuItem: string) => (
              <li key={menuItem}>
                <MenuItem subject={menuItem} />
              </li>
            ))}
          </ul>
        </HStack>
      </nav>
    </Container>
  );
};

export default Navbar;
