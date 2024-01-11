import { Resource, core, useArray } from '@tomic/react';
import { FC, PropsWithChildren } from 'react';
import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { ViewTransitionProps } from '../../helpers/ViewTransitionProps';
import { transitionName } from '../../helpers/transitionName';
import { getIconForClass } from '../FolderPage/iconMap';
import { Row } from '../../components/Row';

interface ResourceCardTitleProps {
  resource: Resource;
}

export const ResourceCardTitle: FC<PropsWithChildren<ResourceCardTitleProps>> =
  ({ resource, children }) => {
    const [isA] = useArray(resource, core.properties.isA);
    const Icon = getIconForClass(isA[0]);

    return (
      <TitleRow center gap='1ch'>
        <Icon />
        <AtomicLink subject={resource.getSubject()}>
          <Title subject={resource.getSubject()}>{resource.title}</Title>
        </AtomicLink>
        {children}
      </TitleRow>
    );
  };

const Title = styled.h2<ViewTransitionProps>`
  font-size: 1.4rem;
  margin: 0;
  ${props => transitionName('page-title', props.subject)};
  white-space: nowrap;
  text-overflow: ellipsis;
`;

const TitleRow = styled(Row)`
  max-width: 100%;
  height: 2rem;
  overflow: hidden;
  margin-bottom: ${({ theme }) => theme.margin}rem;
  color: ${({ theme }) => theme.colors.textLight};

  svg {
    min-width: 1em;
  }
`;
