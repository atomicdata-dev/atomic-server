/** API availability only; this does not promise that a credential provider
 * supports passkeys or the PRF extension used for encrypted recovery. */
export function hasPasskeyApi(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.isSecureContext === true &&
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.create === 'function' &&
    typeof navigator.credentials?.get === 'function'
  );
}
