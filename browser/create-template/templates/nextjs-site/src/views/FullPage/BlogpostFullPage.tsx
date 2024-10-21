import { Page } from "@/ontologies/website";
import { Resource } from "@tomic/lib";

const BlogpostFullPage = ({ resource }: { resource: Resource<Page> }) => {
  return <div>{resource.title} BlogPostPage</div>;
};

export default BlogpostFullPage;
