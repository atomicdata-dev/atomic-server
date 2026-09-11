import { describe, expect, it } from 'vitest';
import { resolveDemoSpeaker } from './messageSpeaker';

describe('scripted demo speakers', () => {
  const manifest = { drive: 'demo', personas: { mara: 'mara' } };
  it('shows Mara for her local demo speech instead of the signing user', () => {
    expect(resolveDemoSpeaker('dev-user', 'mara', 'demo', true, manifest)).toBe('mara');
  });
  it('keeps verified authorship outside the local demo and for unknown speakers', () => {
    expect(resolveDemoSpeaker('real-user', 'mara', 'demo', false, manifest)).toBe('real-user');
    expect(resolveDemoSpeaker('real-user', 'mara', 'other', true, manifest)).toBe('real-user');
    expect(resolveDemoSpeaker('real-user', 'stranger', 'demo', true, manifest)).toBe('real-user');
  });
});
