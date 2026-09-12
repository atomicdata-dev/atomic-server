import { describe, expect, it } from 'vitest';
import { errorMessageFromResponse } from './error.js';
import { core } from './ontologies/core.js';

describe('errorMessageFromResponse', () => {
  it('pulls the description out of a JSON-AD error', () => {
    // The real shape: a sentence, buried under a class list and a Loro update.
    const body = JSON.stringify({
      [core.properties.description]:
        '`awfawf` is not a URL: relative URL without a base',
      'https://atomicdata.dev/properties/errorCode': 0,
      'https://atomicdata.dev/properties/isA': [
        'https://atomicdata.dev/classes/Error',
      ],
      'https://atomicdata.dev/properties/loroUpdate': 'bG9ybwAAAA…',
    });

    expect(errorMessageFromResponse(body, 500)).toBe(
      '`awfawf` is not a URL: relative URL without a base',
    );
  });

  it('falls back to a short body that is not one of ours', () => {
    expect(errorMessageFromResponse('Bad Request', 400)).toBe('Bad Request');
  });

  it('does not paste a whole error page into a toast', () => {
    const html = `<html>${'x'.repeat(400)}</html>`;

    expect(errorMessageFromResponse(html, 502)).toBe('Request failed (502)');
  });

  it('says something when the body says nothing', () => {
    expect(errorMessageFromResponse('', 500)).toBe('Request failed (500)');
    expect(errorMessageFromResponse('   ', 500)).toBe('Request failed (500)');
  });

  it('ignores a JSON body with no description', () => {
    expect(errorMessageFromResponse('{"a":1}', 418)).toBe('{"a":1}');
  });
});
