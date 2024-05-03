import { FaPlus } from 'react-icons/fa';
import { styled } from 'styled-components';
import { ViewProps } from './FolderDisplayStyle';
import {
  GridCard,
  GridItemTitle,
  GridItemWrapper,
} from './GridItem/components';
import { ResourceGridItem } from './GridItem/ResourceGridItem';

export function GridView({
  subResources,
  onNewClick,
  showNewButton,
}: ViewProps): JSX.Element {
  return (
    <Grid>
      {Array.from(subResources.values()).map(resource => (
        <ResourceGridItem
          subject={resource.getSubject()}
          key={resource.getSubject()}
        />
      ))}
      {showNewButton && (
        <GridItemWrapper>
          <NewCard as='button' onClick={onNewClick} title='Create new resource'>
            <FaPlus />
          </NewCard>
          <GridItemTitle>New Resource</GridItemTitle>
        </GridItemWrapper>
      )}
    </Grid>
  );
}

const Grid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
  width: var(--container-width);
  margin-inline: auto;
  gap: 3rem;
`;

const NewCard = styled(GridCard)`
  background-color: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  cursor: pointer;
  display: grid;
  place-items: center;
  font-size: 3rem;
  color: ${p => p.theme.colors.textLight};
  transition:
    color 0.1s ease-in-out,
    font-size 0.1s ease-out,
    box-shadow 0.1s ease-in-out;
  ${GridItemWrapper}:hover &,
  ${GridItemWrapper}:focus & {
    color: ${p => p.theme.colors.main};
    font-size: 3.8rem;
  }

  :active {
    font-size: 3rem;
  }
`;
