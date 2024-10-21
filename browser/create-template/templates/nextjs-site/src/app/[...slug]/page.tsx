import { getCurrentResource } from "@/atomic/getCurrentResource";
import { env } from "@/env";
import FullPageView from "@/views/FullPage/FullPageView";

const Page = async ({
  params,
}: {
  params: {
    slug: string[];
  };
}) => {
  const resourceUrl = new URL(
    `${env.NEXT_PUBLIC_ATOMIC_SERVER_URL}/${params.slug.join("/")}`
  );
  const resource = await getCurrentResource(resourceUrl);

  if (!resource) {
    return { notFound: true };
  }

  return <FullPageView subject={resource.subject} />;
};

export default Page;
