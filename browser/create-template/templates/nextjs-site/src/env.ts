import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  server: {},
  client: {
    NEXT_PUBLIC_ATOMIC_SERVER_URL: z.string().url(),
    NEXT_PUBLIC_WEBSITE_RESOURCE: z.string().url(),
  },

  // For Next.js >= 13.4.4, you only need to destructure client variables:
  experimental__runtimeEnv: {
    NEXT_PUBLIC_ATOMIC_SERVER_URL: process.env.NEXT_PUBLIC_ATOMIC_SERVER_URL,
    NEXT_PUBLIC_WEBSITE_RESOURCE: process.env.NEXT_PUBLIC_WEBSITE_RESOURCE,
  },
});
