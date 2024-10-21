import styles from "./Container.module.css";
import { clsx } from "clsx";

const Container = ({ children }: { children: React.ReactNode }) => {
  return <div className={styles.container}>{children}</div>;
};

export default Container;
