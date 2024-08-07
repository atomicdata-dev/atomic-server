import { styled } from 'styled-components';
import { Image } from '@tomic/react';
import { InnerWrapper } from '../views/FolderPage/GridItem/components';

interface ThumbnailProps {
  subject: string;
  style?: React.CSSProperties | undefined;
}

export function Thumbnail({ subject, style }: ThumbnailProps): JSX.Element {
  return (
    <InnerWrapper>
      <StyledImage
        subject={subject}
        alt=''
        loading='lazy'
        style={style}
        sizeIndication={{
          '55px': 100,
          default: 30,
        }}
      />
    </InnerWrapper>
  );
}

const StyledImage = styled(Image)`
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: center;
`;
