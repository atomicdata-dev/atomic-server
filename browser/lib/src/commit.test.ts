import { describe, it } from 'vitest';
import {
  CommitBuilder,
  generatePublicKeyFromPrivate,
  parseAndApplyCommit,
  serializeDeterministically,
  signToBase64,
} from './commit.js';
import { Store } from './store.js';

describe('Commit signing and keys', () => {
  const privateKey = 'CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=';
  const publicKey = '7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=';
  const agentSubject =
    'http://localhost/agents/7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=';
  const subject = 'https://localhost/new_thing';

  it('creates the right public key', async ({ expect }) => {
    const generatedPublickey = await generatePublicKeyFromPrivate(privateKey);
    expect(generatedPublickey).to.equal(publicKey);
  });

  it('signs a commit with the right signature', async ({ expect }) => {
    const signatureCorrect =
      'kLh+mxy/lgFD6WkbIbhJANgRhyu39USL9up1zCmqU8Jmc+4rlvLZwxSlfxKTISP2BiXLSiz/5NJZrN5XpXJ/Cg==';
    const serializedCommitRust =
      '{"https://atomicdata.dev/properties/createdAt":0,"https://atomicdata.dev/properties/isA":["https://atomicdata.dev/classes/Commit"],"https://atomicdata.dev/properties/set":{"https://atomicdata.dev/properties/description":"Some value","https://atomicdata.dev/properties/shortname":"someval"},"https://atomicdata.dev/properties/signature":"kLh+mxy/lgFD6WkbIbhJANgRhyu39USL9up1zCmqU8Jmc+4rlvLZwxSlfxKTISP2BiXLSiz/5NJZrN5XpXJ/Cg==","https://atomicdata.dev/properties/signer":"http://localhost/agents/7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=","https://atomicdata.dev/properties/subject":"https://localhost/new_thing"}';
    const createdAt = 0;

    const commitBuilder = new CommitBuilder(subject, {
      set: new Map([
        ['https://atomicdata.dev/properties/description', 'Some value'],
        ['https://atomicdata.dev/properties/shortname', 'someval'],
      ]),
    });

    const commit = await commitBuilder.signAt(
      agentSubject,
      privateKey,
      createdAt,
    );
    const sig = commit.signature;
    const serialized = serializeDeterministically(commit);
    expect(serialized).to.equal(serializedCommitRust);
    expect(sig).to.equal(signatureCorrect);
  });

  it('signs any string correctly', async ({ expect }) => {
    const input = 'val';
    const correct_signature_rust =
      'YtDR/xo0272LHNBQtDer4LekzdkfUANFTI0eHxZhITXnbC3j0LCqDWhr6itNvo4tFnep6DCbev5OKAHH89+TDA==';
    const signature = await signToBase64(input, privateKey);
    expect(signature).to.equal(correct_signature_rust);
  });
});

describe('Commit parse and apply', () => {
  const store = new Store();
  const exampleCommit = `
  {
    "@id": "https://atomicdata.dev/commits/VCHGWxax6j4pPMJWelwpSHVOL+W2R2A0vjFdSpH/HhIZxE6hyaUTtPfKjgWGNhsUsQske4yHIdqc/QsQhV03DA==",
    "https://atomicdata.dev/properties/createdAt": 1627561366516,
    "https://atomicdata.dev/properties/isA": [
      "https://atomicdata.dev/classes/Commit"
    ],
    "https://atomicdata.dev/properties/set": {
      "https://atomicdata.dev/properties/description": "My new string"
    },
    "https://atomicdata.dev/properties/signature": "VCHGWxax6j4pPMJWelwpSHVOL+W2R2A0vjFdSpH/HhIZxE6hyaUTtPfKjgWGNhsUsQske4yHIdqc/QsQhV03DA==",
    "https://atomicdata.dev/properties/signer": "https://atomicdata.dev/agents/8S2U/viqkaAQVzUisaolrpX6hx/G/L3e2MTjWA83Rxk=",
    "https://atomicdata.dev/properties/subject": "https://atomicdata.dev/element/cn6ymb8s8mc"
  }`;
  it('parses and applies a Commit correctly', async ({ expect }) => {
    parseAndApplyCommit(exampleCommit, store);
    const resource = await store.getResource(
      'https://atomicdata.dev/element/cn6ymb8s8mc',
    );
    const description = resource
      .get('https://atomicdata.dev/properties/description')!
      .toString();
    expect(description).to.equal('My new string');
  });
});
