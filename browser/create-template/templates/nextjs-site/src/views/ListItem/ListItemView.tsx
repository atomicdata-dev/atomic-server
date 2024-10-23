import { useResource } from '@tomic/react';
import { website } from '@/ontologies/website';
import BlogListItem from './BlogListItem';
import DefaultView from '@/views/DefaultView';
import { store } from '@/app/store';

const ListItemView = async ({ subject }: { subject: string }) => {
  const listItem = await store.getResource(subject);

  const Component = listItem.matchClass(
    {
      [website.classes.blogpost]: BlogListItem,
    },
    DefaultView,
  );

  return <Component resource={listItem} />;
};

export default ListItemView;
