import { website } from '@/ontologies/website';
import PageFullPage from './PageFullPage';
import BlogIndexPageFullPage from './BlogIndexPageFullPage';
import BlogpostFullPage from './BlogpostFullPage';
import DefaultFullPage from './DefaultFullPage';
import { useCurrentSubject } from '@/app/context/CurrentSubjectContext';
import { store } from '@/app/store';

const FullPageView = async ({ subject }: { subject: string }) => {
  const resource = await store.getResource(subject);
  // const { setCurrentSubject } = useCurrentSubject();

  const Component = resource.matchClass(
    {
      [website.classes.page]: PageFullPage,
      [website.classes.blogIndexPage]: BlogIndexPageFullPage,
      [website.classes.blogpost]: BlogpostFullPage,
    },
    DefaultFullPage,
  );

  // setCurrentSubject(subject);

  return <Component resource={resource} />;
};

export default FullPageView;
