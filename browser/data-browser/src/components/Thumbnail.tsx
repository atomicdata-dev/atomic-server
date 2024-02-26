import { styled } from 'styled-components';
import { InnerWrapper } from '../views/FolderPage/GridItem/components';

interface ThumbnailProps {
  src: string | undefined;
  style?: React.CSSProperties | undefined;
}

export function Thumbnail({ src, style }: ThumbnailProps): JSX.Element {
  if (src === undefined) {
    return <TextWrapper>No preview available</TextWrapper>;
  }

  return (
    <InnerWrapper>
      <Image src={src} alt='' loading='lazy' style={style} />
    </InnerWrapper>
  );
}

const Image = styled.img`
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: center;
`;

const TextWrapper = styled(InnerWrapper)`
  display: grid;
  place-items: center;
  color: ${p => p.theme.colors.textLight};
`;
