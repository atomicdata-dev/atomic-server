import { type Resource } from "@tomic/react";
import Image from "next/image";

const BlogListItem = ({ resource }: { resource: Resource }) => {
  const formatter = new Intl.DateTimeFormat("default", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const date = formatter.format(new Date(resource.props.date));

  return (
    <a className="card" href={resource.props.href}>
      <div className="image-wrapper">
        <Image src={resource.props.coverImage} alt="" />
      </div>
      <div className="card-content">
        <div className="publish-date">{date}</div>
        <h2>{resource.title}</h2>
        <p>{resource.props.description.slice(0, 300)}...</p>
      </div>
    </a>
  );
};

export default BlogListItem;
