import Container from './Layout/Container';
import HStack from './Layout/HStack';
import { env } from '@/env';
import { Website } from '@/ontologies/website';
import MenuItem from '@/views/MenuItem/MenuItem';
import styles from './Navbar.module.css';
import { store } from '@/app/store';
import Link from 'next/link';

const Navbar = async () => {
  const site = await store.getResource<Website>(
    env.NEXT_PUBLIC_WEBSITE_RESOURCE,
  );

  return (
    <Container>
      <nav className={styles.nav}>
        <HStack align='center' justify='space-between' wrap>
          <Link href='/' className={styles.title}>
            {site.title}
          </Link>
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
