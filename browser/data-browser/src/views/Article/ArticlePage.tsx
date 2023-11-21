import {
  classes,
  getTimestampNow,
  properties,
  useCanWrite,
  useChildren,
  useString,
} from '@tomic/react';
import { useCallback } from 'react';
import { styled } from 'styled-components';
import { CommitDetail } from '../../components/CommitDetail';
import { ContainerWide } from '../../components/Containers';
import { EditableTitle } from '../../components/EditableTitle';
import UploadForm from '../../components/forms/UploadForm';
import { NewCard } from '../../components/NewCard';
import { useCreateAndNavigate } from '../../components/NewInstanceButton';
import { Column } from '../../components/Row';
import ResourceCard from '../Card/ResourceCard';
import { ResourcePageProps } from '../ResourcePage';
import { ArticleCover } from './ArticleCover';
import { ArticleDescription } from './ArticleDescription';

export function ArticlePage({ resource }: ResourcePageProps): JSX.Element {
  const [lastCommit] = useString(resource, properties.commit.lastCommit);

  const [canEdit] = useCanWrite(resource);
  const children = useChildren(resource);

  const createAndNavigate = useCreateAndNavigate(
    classes.article,
    resource.getSubject(),
  );

  const createNewArticle = useCallback(() => {
    createAndNavigate('article', {
      [properties.isA]: [classes.article],
      [properties.name]: 'New Article',
      [properties.publishedAt]: getTimestampNow(),
      [properties.description]: '',
    });
  }, [createAndNavigate]);

  return (
    <>
      <Column gap='2rem'>
        <ArticleContainer>
          <Content>
            <Column>
              <ArticleCover resource={resource} canEdit={canEdit} />
              <HeadingWrapper>
                <EditableTitle resource={resource} />
                <CommitDetail commitSubject={lastCommit} />
              </HeadingWrapper>
              <ArticleDescription resource={resource} canEdit={canEdit} />
              <UploadForm parentResource={resource} />
            </Column>
          </Content>
        </ArticleContainer>
        <ChildrenSection>
          <ContainerWider>
            <h2>Children</h2>
            <Grid>
              {children.map(child => (
                <Height key={child}>
                  <ResourceCard subject={child} />
                </Height>
              ))}
              {canEdit && (
                <Height>
                  <NewCard onClick={createNewArticle} />
                </Height>
              )}
            </Grid>
          </ContainerWider>
        </ChildrenSection>
      </Column>
    </>
  );
}

const Content = styled.div`
  position: relative;
  background-color: ${({ theme }) => theme.colors.bg};
  padding: ${({ theme }) => theme.margin}rem;
  border-radius: ${({ theme }) => theme.radius};
  border: solid 1px ${({ theme }) => theme.colors.bg2};
  overflow: hidden;
`;

const HeadingWrapper = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;

  h1 {
    margin-bottom: 0;
  }
`;

const ArticleContainer = styled(ContainerWide)`
  padding-bottom: 0;
  &:last-child {
    padding-bottom: 10rem;
  }
`;

const ChildrenSection = styled.section`
  width: 100%;
  background-color: ${({ theme }) => theme.colors.bg};
  padding-top: ${({ theme }) => theme.margin}rem;
`;

const Grid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(20rem, 1fr));
  gap: ${({ theme }) => theme.margin}rem;
`;

const ContainerWider = styled(ContainerWide)`
  width: min(100%, 80rem);
`;

const Height = styled.div`
  min-height: 12rem;
  & > * {
    height: 100%;
  }
`;
