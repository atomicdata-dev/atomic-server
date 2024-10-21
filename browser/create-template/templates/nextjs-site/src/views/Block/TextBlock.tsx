import { Resource } from "@tomic/lib";
import { remark } from "remark";
import html from "remark-html";
import matter from "gray-matter";
import styles from "./TextBlock.module.css";

const TextBlock = ({ resource }: { resource: Resource }) => {
  const matterResult = matter(resource.props.description);

  const processed = remark().use(html).processSync(matterResult.content);

  const content = processed.toString();

  return (
    <div
      className={styles.wrapper}
      dangerouslySetInnerHTML={{ __html: content }}
    />
  );
};

export default TextBlock;
