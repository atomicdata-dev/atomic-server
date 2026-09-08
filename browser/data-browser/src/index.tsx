import { reactErrorHandler } from '@sentry/react';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import App from './App';
import { initSentry } from './helpers/sentry';
// Side-effect import: installs a global capture-phase `wheel` listener
// before any route mounts. CanvasPage uses it to ignore momentum-scroll
// tails carried over from the previous view (see the file's doc-comment).
import './helpers/wheelSession';
// Side-effect import: queues atomic:// deep links forwarded by the Tauri
// shell so a link that launched the app isn't lost before React mounts.
import './helpers/deepLinkQueue';

/**
 * Polyfill for crypto.subtle.digest in non-secure contexts (e.g., local IPs).
 * Some dependencies like @openrouter/sdk and hashery use this, but browsers
 * disable it on anything but localhost/HTTPS.
 */
if (
  typeof window !== 'undefined' &&
  (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.digest)
) {
  console.warn(
    'Atomic Server: Providing a polyfill for crypto.subtle.digest in an insecure context.',
  );

  // Ensure the object hierarchy exists
  if (!window.crypto) {
    // @ts-ignore
    window.crypto = {};
  }

  if (!window.crypto.subtle) {
    // @ts-ignore
    window.crypto.subtle = {};
  }

  // Only patch if missing (though the outer IF already checks this)
  if (!window.crypto.subtle.digest) {
    window.crypto.subtle.digest = async (algorithm, data) => {
      const algoStr =
        typeof algorithm === 'string'
          ? algorithm.toUpperCase()
          : // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (algorithm as unknown as { name: string }).name.toUpperCase();

      const input =
        data instanceof Uint8Array ? data : new Uint8Array(data as ArrayBuffer);

      if (algoStr === 'SHA-256' || algoStr === 'SHA256') {
        return sha256(input).buffer as ArrayBuffer;
      }

      if (algoStr === 'SHA-512' || algoStr === 'SHA512') {
        return sha512(input).buffer as ArrayBuffer;
      }

      throw new Error(
        `Polyfill: Unsupported hash algorithm: ${algoStr}. Only SHA-256 and SHA-512 are supported in this context.`,
      );
    };
  }
}

// Before the first render, so errors thrown while mounting are reported too.
initSentry();

const root = createRoot(document.getElementById('root')!, {
  onCaughtError: reactErrorHandler(),
  onUncaughtError: reactErrorHandler(),
  onRecoverableError: reactErrorHandler(),
});
root.render(
  <StrictMode>
    <App />
  </StrictMode>,
);
