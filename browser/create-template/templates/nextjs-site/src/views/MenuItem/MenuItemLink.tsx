import type { MenuItemSnapshot } from './MenuItem';
import { website } from '@/ontologies/website';
import { unknownSubject, Resource } from '@tomic/lib';
import styles from './MenuItemLink.module.css';
import clsx from 'clsx';
import { useResource } from '@tomic/react';
import Link from 'next/link';

const MenuItemLink = ({
  resource,
  active = false,
  initial,
}: {
  resource: Resource;
  active?: boolean;
  initial?: MenuItemSnapshot;
}) => {
  const page = useResource(resource.subject ?? unknownSubject);

  const pageHrefValue = useResource(page.get(website.properties.linksTo));

  const href =
    pageHrefValue.get(website.properties.href) ??
    resource.props.externalLink ??
    initial?.href ??
    '#';

  return (
    <Link
      href={href}
      className={clsx(styles.link, { [styles.linkActive]: active })}
      aria-current={active ? 'page' : 'false'}
    >
      {resource.loading ? (initial?.title ?? '') : page.title}
    </Link>
  );
};

export default MenuItemLink;
