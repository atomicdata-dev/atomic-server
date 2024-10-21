import { website } from "@/ontologies/website";
import { unknownSubject, Resource } from "@tomic/lib";
import { useValue, useResource } from "@tomic/react";
import styles from "./MenuItemLink.module.css";
import clsx from "clsx";

const MenuItemLink = ({
  resource,
  active = false,
}: {
  resource: Resource;
  active?: boolean;
}) => {
  const page = useResource(resource.props.linksTo ?? unknownSubject);
  const [pageHrefValue] = useValue(page, website.properties.href);

  const href = pageHrefValue ?? resource.props.externalLink ?? "#";

  return (
    <>
      <a
        href={href}
        className={clsx(styles.link, { [styles.linkActive]: active })}
        aria-current={active ? "page" : "false"}
      >
        {resource.title}
      </a>
    </>
  );
};

export default MenuItemLink;
