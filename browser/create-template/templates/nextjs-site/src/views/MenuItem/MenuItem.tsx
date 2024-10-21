import type { MenuItem } from "@/ontologies/website";
import { unknownSubject, useResource } from "@tomic/react";
import MenuItemLink from "./MenuItemLink";
import styles from "./MenuItem.module.css";
import { useEffect, useRef } from "react";

const MenuItem = ({ subject }: { subject: string }) => {
  const menuItem = useResource<MenuItem>(subject ?? unknownSubject);

  const id = (Math.random().toString(36) + "00000000000000000").slice(2, 10);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  const closePopover = () => {
    if (popoverRef.current) {
      popoverRef.current.hidePopover();
    }
  };

  const handleFocusOut = (
    event: React.FocusEvent<HTMLDivElement | HTMLButtonElement>
  ) => {
    if (
      !event.relatedTarget ||
      !event.currentTarget.contains(event.relatedTarget as Node)
    ) {
      closePopover();
    }
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        buttonRef.current &&
        popoverRef.current &&
        !buttonRef.current.contains(e.target as Node) &&
        !popoverRef.current.contains(e.target as Node)
      ) {
        closePopover();
      }
    };

    document.addEventListener("click", handleClickOutside);
    return () => {
      document.removeEventListener("click", handleClickOutside);
    };
  }, []);

  return menuItem.props.subItems && menuItem.props.subItems.length > 0 ? (
    <>
      <button
        className={styles.button}
        popovertarget={id}
        popovertargetaction="toggle"
      >
        {menuItem.title}
      </button>

      <div
        id={id}
        className={styles.subMenu}
        popover="manual"
        ref={popoverRef}
        tabIndex={-1}
        onBlur={handleFocusOut}
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
