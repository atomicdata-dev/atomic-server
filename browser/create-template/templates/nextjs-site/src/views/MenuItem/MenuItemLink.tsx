import { website } from '@/ontologies/website';
import { unknownSubject, Resource } from '@tomic/lib';
import styles from './MenuItemLink.module.css';
import clsx from 'clsx';
import { store } from '@/app/store';

const MenuItemLink = async ({
  resource,
  active = false,
}: {
  resource: Resource;
  active?: boolean;
}) => {
  const page = await store.getResource(resource.subject ?? unknownSubject);

  const pageHrefValue = await store.getResource(
    page.get(website.properties.linksTo),
  );

  const href =
    pageHrefValue.get(website.properties.href) ??
    resource.props.externalLink ??
    '#';

  return (
    <a
      href={href}
      className={clsx(styles.link, { [styles.linkActive]: active })}
      aria-current={active ? 'page' : 'false'}
    >
      {resource.title}
    </a>
  );
};

export default MenuItemLink;
