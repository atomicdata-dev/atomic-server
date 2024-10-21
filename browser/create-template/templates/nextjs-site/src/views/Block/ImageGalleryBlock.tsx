import { Resource } from "@tomic/lib";
import { Image } from "@tomic/react";
import styles from "./ImageGalleryBlock.module.css";

const ImageGalleryBlock = ({ resource }: { resource: Resource }) => {
  return (
    <>
      {resource.props.name ? <h2>{resource.props.name}</h2> : null}

      <div className={styles.wrapper}>
        {resource.props.images?.map((image: string, index: number) => (
          <div key={index} className={styles.image}>
            <Image subject={image} alt="" />
          </div>
        ))}
      </div>
    </>
  );
};

export default ImageGalleryBlock;
