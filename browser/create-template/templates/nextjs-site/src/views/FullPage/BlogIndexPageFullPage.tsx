import Container from '@/components/Layout/Container';
import type { Page } from '@/ontologies/website';
import { type Resource, core } from '@tomic/lib';
import styles from './BlogIndexPageFullPage.module.css';
import VStack from '@/components/Layout/VStack';
import HStack from '@/components/Layout/HStack';
import Searchbar from '@/components/Searchbar';
import ListItemView from '../ListItem/ListItemView';
// import { useDebounced } from '@/utils';
import { useStore } from '@tomic/react';
import { website } from '@/ontologies/website';
import { getAllBlogposts } from '@/atomic/getAllBlogposts';

const BlogIndexPageFullPage = async ({
  resource,
}: {
  resource: Resource<Page>;
}) => {
  const results = await getAllBlogposts();

  return (
    <Container>
      <div className={styles.wrapper}>
        <VStack>
          <HStack wrap fullWidth align='center' justify='space-between'>
            <h1>{resource.title}</h1>
            {/* <Searchbar
            //   value={search}
            //   handler={handleSearch}
            //   placeholder='Search blogposts...'
            // /> */}
          </HStack>
          <ul>
            {results.map((post: string) => (
              <li key={post}>
                <ListItemView subject={post} />
              </li>
            ))}
          </ul>
        </VStack>
      </div>
    </Container>
  );
};

export default BlogIndexPageFullPage;
