import { env } from '@/env';
import { Store } from '@tomic/lib';

export const store = new Store({
  serverUrl: env.NEXT_PUBLIC_ATOMIC_SERVER_URL,
});
