import { Resource } from '@tomic/lib';
import { Image } from '@/components/Image';
import styles from './ImageGalleryBlock.module.css';
import { Suspense } from 'react';
import { website } from '@/ontologies/website';

const ImageGalleryBlock = async ({ resource }: { resource: Resource }) => {
  return (
    <>
      {resource.props.name ? <h2>{resource.props.name}</h2> : null}

      <div className={styles.wrapper}>
        {resource
          .get(website.properties.images)
          ?.map((image: string, index: number) => (
            <div key={index} className={styles.image}>
              <Image subject={image} alt='' />
            </div>
          ))}
      </div>
    </>
  );
};

export default ImageGalleryBlock;
