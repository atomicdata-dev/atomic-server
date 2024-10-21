"use client";

import { website } from "@/ontologies/website";
import PageFullPage from "./PageFullPage";
import BlogIndexPageFullPage from "./BlogIndexPageFullPage";
import BlogpostFullPage from "./BlogpostFullPage";
import DefaultFullPage from "./DefaultFullPage";
import { useResource } from "@tomic/react";

const FullPageView = ({ subject }: { subject: string }) => {
  const resource = useResource(subject);

  const Component = resource.matchClass(
    {
      [website.classes.page]: PageFullPage,
      [website.classes.blogIndexPage]: BlogIndexPageFullPage,
      [website.classes.blogpost]: BlogpostFullPage,
    },
    DefaultFullPage
  );

  return <Component resource={resource} />;
};

export default FullPageView;
