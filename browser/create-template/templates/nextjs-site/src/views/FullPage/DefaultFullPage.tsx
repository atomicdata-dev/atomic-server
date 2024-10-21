import Container from "@/components/Layout/Container";
import { Resource } from "@tomic/lib";

const DefaultFullPage = ({ resource }: { resource: Resource }) => {
  return (
    <Container>
      <h1>{resource.title}</h1>
      <p>No valid page view for resource {resource.getClasses()}.</p>
    </Container>
  );
};

export default DefaultFullPage;
