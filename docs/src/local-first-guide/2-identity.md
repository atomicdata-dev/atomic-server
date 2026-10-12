# Step 1: an identity that is a key

In the HTTP era the first thing an app did was register a user on a server.
Here the first thing it does is generate a keypair.
That keypair *is* the [Agent](../agents.md): its identifier is derived from the public key, so it exists the moment it is generated and no server has to know about it.

```ts
import { Agent, JSCryptoProvider } from '@tomic/lib';

const SECRET_KEY = 'reading-list.agent-secret';

async function loadOrCreateAgent(): Promise<Agent> {
  const stored = localStorage.getItem(SECRET_KEY);

  if (stored) {
    // 'js' picks the pure-JS Ed25519 implementation. It signs deterministically,
    // which the personal-drive derivation in the next step relies on.
    return Agent.fromSecret(stored, 'js');
  }

  const keys = await Agent.generateKeyPair();
  const subject = `atomic:agent:${keys.publicKey}`;

  // One string that encodes the private key and the subject. This is the
  // account: whoever holds it, is this Agent.
  const secret = Agent.buildSecret(keys.privateKey, subject);
  localStorage.setItem(SECRET_KEY, secret);

  return new Agent(new JSCryptoProvider(keys.privateKey), subject);
}

const agent = await loadOrCreateAgent();
console.log(agent.subject); // atomic:agent:…
```

Three things to notice.

**Nothing left the device.** No request was made. The identifier is valid everywhere already, because anyone who later receives a signature from this Agent can verify it with the public key that is inside the identifier. See [URLs and identifiers](../urls.md).

**The secret is the account.** `localStorage` is fine for a tutorial. A real app keeps it somewhere better: the web app wraps it with a passkey, and native apps use the platform keystore. Losing the secret without a backup means losing the identity, which is the trade-off [local-first](../local-first.md) makes explicit.

**There is no password.** Signing in on a new device means pasting the secret, scanning it, or restoring it from a passkey. It restores *who you are*. Getting *what you have* onto that device is the job of sync, in step 4.

Next: [a Store and a Drive, with no server](3-store-and-drive.md).
