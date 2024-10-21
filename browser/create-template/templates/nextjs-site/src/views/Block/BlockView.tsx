"use client";

import { useResource } from "@tomic/react";
import DefaultView from "../DefaultView";
import TextBlock from "./TextBlock";
import { website } from "@/ontologies/website";
import ImageGalleryBlock from "./ImageGalleryBlock";

const BlockView = ({ subject }: { subject: string }) => {
  const block = useResource(subject);

  const Component = block.matchClass(
    {
      [website.classes.textBlock]: TextBlock,
      [website.classes.imageGalleryBlock]: ImageGalleryBlock,
    },
    DefaultView
  );

  return <Component resource={block} />;
};

export default BlockView;
