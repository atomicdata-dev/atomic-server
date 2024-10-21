import { useResource } from "@tomic/react";
import { website } from "@/ontologies/website";
import BlogListItem from "./BlogListItem";
import DefaultView from "@/views/DefaultView";

const ListItemView = ({ subject }: { subject: string }) => {
  const listItem = useResource(subject);

  const Component = listItem.matchClass(
    {
      [website.classes.blogpost]: BlogListItem,
    },
    DefaultView
  );

  return <Component resource={listItem} />;
};

export default ListItemView;
