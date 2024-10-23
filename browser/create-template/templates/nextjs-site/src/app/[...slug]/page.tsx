import { getCurrentResource } from '@/atomic/getCurrentResource';
import { env } from '@/env';
import FullPageView from '@/views/FullPage/FullPageView';
import { notFound } from 'next/navigation';

const Page = async (
  props: {
    params: Promise<{
      slug: string[];
    }>;
  }
) => {
  const params = await props.params;
  const resourceUrl = new URL(
    `${env.NEXT_PUBLIC_ATOMIC_SERVER_URL}/${params.slug.join('/')}`,
  );
  const resource = await getCurrentResource(resourceUrl);

  if (!resource) {
    return notFound();
  }

  return <FullPageView subject={resource.subject} />;
};

export default Page;
