import { Agent, JSCryptoProvider, useStore } from '@tomic/react';
import { useCallback, useState } from 'react';
import toast from 'react-hot-toast';
import { useSettings } from '../helpers/AppSettings';
import { saveAgentToIDB } from '../helpers/agentStorage';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from './useNavigateWithTransition';

/** Default dev server. Used as a fallback when the page wasn't loaded from
 *  an atomic-server origin (e.g. when developing the data-browser via Vite
 *  on localhost:6747). When the SPA is being served by an atomic-server
 *  directly — production, dagger CI, or any non-Vite host — we use the
 *  page's own origin so dev-drive talks to the server it came from. */
export const DEV_SERVER = 'http://localhost:9883';
export const DEV_DRIVE_TESTID = 'dev-drive-button';

/** In drive description; server `/prunetests` deletes drives containing this. Keep in sync with `prunetests.rs`. */
export const DEV_DRIVE_PRUNE_MARKER = '[atomic-data:dev-drive]';

const DEV_DRIVE_DISPLAY_NAME = 'Dev drive';

/** Name set on the dev-drive Agent resource. Visible anywhere the agent's
 *  resource title is rendered — commit author lines, chat messages, etc.
 *  E2E tests can assert against this exact string. */
export const DEV_DRIVE_AGENT_NAME = 'Dev User';

/** Resolve the atomic-server URL the dev drive should target. If the SPA
 *  is served by atomic-server itself (any non-Vite origin), use the same
 *  origin. Vite-served pages fall back to the hardcoded default. */
function resolveDevServer(): string {
  if (typeof window === 'undefined') return DEV_SERVER;

  // The SPA's own origin IS the server, except on the Vite dev server (which
  // serves the SPA on a separate port). There, `VITE_ATOMIC_SERVER_URL`
  // (see `.env.development`) overrides to the real server — no hardcoded vite
  // port here.
  return import.meta.env.VITE_ATOMIC_SERVER_URL ?? window.location.origin;
}

/**
 * Creates a fresh agent and drive on the current atomic-server (page origin
 * unless we're loaded from the Vite dev server, in which case localhost:9883)
 * and switches to it. Only intended for development / E2E-test use.
 */
const CLIPBOARD_DENIED = 'NotAllowedError';

export function useDevDrive() {
  const store = useStore();
  const { setAgent, setDrive, setServer } = useSettings();
  const navigate = useNavigateWithTransition();
  const [loading, setLoading] = useState(false);

  const createDevDrive = useCallback(async () => {
    setLoading(true);

    try {
      setServer(resolveDevServer());

      const agentKeys = await Agent.generateKeyPair();
      const agentDID = `did:ad:agent:${agentKeys.publicKey}`;
      const agentProvider = new JSCryptoProvider(agentKeys.privateKey);
      const newAgent = new Agent(agentProvider, agentDID);

      store.setAgent(newAgent);
      await store.waitForClientDb(10_000);

      // `agentName` pipes `DEV_DRIVE_AGENT_NAME` into the same
      // agent-resource save that `createDrive` already does (to wire up
      // `privateDrive` + `drives`). The agent shows up as "Dev User"
      // wherever its resource is rendered (commit author lines, chat
      // messages, etc.). E2E tests assert against this constant.
      const driveResource = await store.createDrive(DEV_DRIVE_DISPLAY_NAME, {
        description: `Created via \`/app/dev-drive\` for local development and E2E. You can remove these with Prune test data on \`/app/prunetests\`. \n\n${DEV_DRIVE_PRUNE_MARKER}`,
        agentName: DEV_DRIVE_AGENT_NAME,
      });

      const finalSecret = Agent.buildSecret(
        agentKeys.privateKey,
        agentDID,
        driveResource.subject,
      );

      // Expose for E2E tests so they can sign in as the same agent on other pages.
      localStorage.setItem('atomic-test.dev-drive-secret', finalSecret);

      // Copy the agent secret to the clipboard so the dev can paste it
      // into another browser, tab, or device to sign in as the same
      // agent — handy for testing live cursor / collab without manually
      // shuttling the secret out of localStorage. Clipboard access can
      // throw on insecure origins or when the document is hidden;
      // failure is non-fatal — the secret is still in localStorage and
      // surfaced via the toast either way.
      let copied = false;

      try {
        if (document.hasFocus() && navigator.userActivation?.isActive) {
          await navigator.clipboard.writeText(finalSecret);
          copied = true;
        }
      } catch (e) {
        if (
          !(
            e &&
            typeof e === 'object' &&
            'name' in e &&
            e.name === CLIPBOARD_DENIED
          )
        ) {
          console.error('[DevDrive] clipboard.writeText failed:', e);
        }
      }

      toast.success(
        copied
          ? 'Dev agent created — secret copied to clipboard'
          : 'Dev agent created — secret available in localStorage (clipboard write blocked)',
      );

      await saveAgentToIDB(finalSecret);
      const updatedAgent = await Agent.fromSecret(finalSecret);
      store.setAgent(updatedAgent);
      setAgent(updatedAgent);
      setDrive(driveResource.subject);
      navigate(constructOpenURL(driveResource.subject));
    } finally {
      setLoading(false);
    }
  }, [store, setAgent, setDrive, setServer, navigate]);

  return { createDevDrive, loading };
}
