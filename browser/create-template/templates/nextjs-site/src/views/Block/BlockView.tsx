import DefaultView from '../DefaultView';
import TextBlock from './TextBlock';
import { website } from '@/ontologies/website';
import ImageGalleryBlock from './ImageGalleryBlock';
import { store } from '@/app/store';

const BlockView = async ({ subject }: { subject: string }) => {
  const block = await store.getResource(subject);

  const Component = block.matchClass(
    {
      [website.classes.textBlock]: TextBlock,
      [website.classes.imageGalleryBlock]: ImageGalleryBlock,
    },
    DefaultView,
  );

  return <Component resource={block} />;
};

export default BlockView;
