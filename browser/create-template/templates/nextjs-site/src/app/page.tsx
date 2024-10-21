import FullPageView from "@/views/FullPage/FullPageView";
import { notFound } from "next/navigation";
import { getCurrentResource } from "@/atomic/getCurrentResource";
import { env } from "@/env";

export default async function Page() {
  const url = new URL(env.NEXT_PUBLIC_ATOMIC_SERVER_URL);
  const resource = await getCurrentResource(url);

  if (!resource) {
    return notFound();
  }

  return <FullPageView subject={resource.subject} />;
}
