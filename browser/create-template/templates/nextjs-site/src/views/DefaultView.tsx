import { Resource, useResource } from "@tomic/react";

const DefaultView = ({ resource }: { resource: Resource }) => {
  const subjectResource = useResource(resource.subject);

  return <p>No supported view for {subjectResource.title}.</p>;
};

export default DefaultView;
