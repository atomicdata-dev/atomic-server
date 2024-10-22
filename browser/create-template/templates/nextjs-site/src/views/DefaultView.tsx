import { store } from '@/app/store';
import { Resource } from '@tomic/react';

const DefaultView = async ({ resource }: { resource: Resource }) => {
  // const subjectResource = useResource(resource.subject);
  const subjectResource = await store.getResource(resource.subject);

  return <p>No supported view for {subjectResource.title}.</p>;
};

export default DefaultView;
