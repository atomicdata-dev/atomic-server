import { afterEach, describe, expect, it, vi } from 'vitest';
import { hasPasskeyApi } from './passkeySupport';

afterEach(() => vi.unstubAllGlobals());

describe('passkey API availability', () => {
  it('rejects embedded browsers without PublicKeyCredential', () => {
    vi.stubGlobal('window', { isSecureContext: true });
    vi.stubGlobal('navigator', { credentials: { create() {}, get() {} } });
    expect(hasPasskeyApi()).toBe(false);
  });

  it('requires both credential operations and a secure context', () => {
    vi.stubGlobal('window', {
      isSecureContext: true,
      PublicKeyCredential: class {},
    });
    vi.stubGlobal('navigator', { credentials: { get() {} } });
    expect(hasPasskeyApi()).toBe(false);
    vi.stubGlobal('navigator', { credentials: { create() {}, get() {} } });
    expect(hasPasskeyApi()).toBe(true);
    vi.stubGlobal('window', {
      isSecureContext: false,
      PublicKeyCredential: class {},
    });
    expect(hasPasskeyApi()).toBe(false);
  });
});
