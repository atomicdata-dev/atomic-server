import { useEffect, useState } from 'react';
import { randomUUID } from '@tomic/lib';
import { sha256 } from '@noble/hashes/sha2.js';
import { ButtonLink } from '../ButtonLink';
import { paths } from '../../routes/paths';

const TEXT = 'Login with OpenRouter';
const AUTH_ENDPOINT = 'https://openrouter.ai/auth';

function createSHA256CodeChallenge(input: string): string {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = sha256(data);

  // Convert ArrayBuffer to base64url string
  const base64String = btoa(String.fromCharCode(...hash));

  // Convert base64 to base64url
  return base64String
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

const buildUrl = (challenge: string) => {
  const url = new URL(AUTH_ENDPOINT);

  url.searchParams.set(
    'callback_url',
    `${location.origin}${paths.linkOpenRouter}`,
  );
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');

  return url.toString();
};

export const OpenRouterLoginButton = () => {
  const [challenge, setChallenge] = useState<string | null>(null);

  useEffect(() => {
    const verifier = randomUUID();
    const generatedChallenge = createSHA256CodeChallenge(verifier);
    setChallenge(generatedChallenge);
    // Stored in localStorage (not sessionStorage) so the verifier survives the
    // OpenRouter round-trip even if the callback lands in a different tab or a
    // fresh session. It is removed again as soon as the code is exchanged.
    localStorage.setItem('atomic.ai.openrouter-code-verifier', verifier);
  }, []);

  if (!challenge) {
    return <ButtonLink href='#'>{TEXT}</ButtonLink>;
  }

  return <ButtonLink href={buildUrl(challenge)}>{TEXT}</ButtonLink>;
};
