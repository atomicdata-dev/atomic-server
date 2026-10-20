import { describe, expect, it } from 'vitest';
import { parseReturnPath, signInPath } from './returnPath';
import { paths } from '../routes/paths';

describe('parseReturnPath', () => {
  it('maps agent to the account settings', () => {
    expect(parseReturnPath('agent')).toBe(paths.agentSettings);
  });

  it('accepts connect links', () => {
    for (const link of [
      '/app/authorize-mcp?server=https%3A%2F%2Fx&client_id=a',
      '/app/connect-agent?key=abc&name=Bot',
    ]) {
      expect(parseReturnPath(link)).toBe(link);
    }
  });

  it('refuses everything else', () => {
    for (const link of [
      null,
      '',
      'https://evil.example/app/connect-agent?key=1',
      '//evil.example/app/connect-agent?key=1',
      '/app/connect-agent',
      '/app/connect-agentx?a=1',
      '/app/settings?x=1',
      ' /app/connect-agent?key=1',
      'javascript:alert(1)',
    ]) {
      expect(parseReturnPath(link)).toBeUndefined();
    }
  });

  it('round-trips a link built by signInPath', () => {
    const here = {
      pathname: '/app/connect-agent',
      search: '?key=a&name=B%20C',
    };
    const param = new URL(signInPath(here), 'http://x').searchParams.get(
      'return_to',
    );

    expect(parseReturnPath(param)).toBe('/app/connect-agent?key=a&name=B%20C');
  });
});
