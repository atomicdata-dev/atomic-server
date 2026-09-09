/* eslint-disable no-shadow -- Playwright callbacks run in a separate browser realm. */
// Transport acceptance only: no AtomicServer, authentication or OPFS involved.
// Run: node browser/e2e/scripts/verify-webrtc.mjs
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { chromium, firefox } from '@playwright/test';
import { build } from 'vite';

const result = await build({
  configFile: false,
  logLevel: 'error',
  build: {
    write: false,
    lib: {
      entry: fileURLToPath(
        new URL('../../lib/src/webrtc-peer.ts', import.meta.url),
      ),
      name: 'AtomicWebrtc',
      formats: ['iife'],
    },
  },
});
const code = (Array.isArray(result) ? result[0] : result).output.find(
  item => item.type === 'chunk',
).code;
const origin = 'http://localhost/';

for (const [name, launcher] of Object.entries({ chromium, firefox })) {
  const browser = await launcher.launch({
    firefoxUserPrefs: { 'network.proxy.type': 0 },
  });

  try {
    const a = await browser.newPage();
    const b = await browser.newPage();

    for (const page of [a, b]) {
      await page.route('http://localhost/**', route =>
        route.fulfill({
          contentType: 'text/html',
          body: '<!doctype html><title>WebRTC transport acceptance</title>',
        }),
      );
      await page.goto(origin);
      await page.addScriptTag({ content: code });
      await page.evaluate(async () => {
        const { WebRtcPeer } = window.AtomicWebrtc;
        window.peer = new WebRtcPeer({}, 15000);
      });
    }

    const offer = await a.evaluate(() => window.peer.createOffer());
    const answer = await b.evaluate(
      offer => window.peer.acceptOffer(offer),
      offer,
    );
    await a.evaluate(answer => window.peer.acceptAnswer(answer), answer);
    await Promise.all(
      [a, b].map(page =>
        page.evaluate(async () => {
          window.pipe = await window.peer.transport;
        }),
      ),
    );
    // Larger than an SCTP message; verify every byte in each direction.
    const length = 1024 * 1024;

    for (const [sender, receiver] of [
      [a, b],
      [b, a],
    ]) {
      const received = receiver.evaluate(async length => {
        const frame = await window.pipe.recv();

        return (
          frame.length === length && frame.every((byte, i) => byte === i % 251)
        );
      }, length);
      await sender.evaluate(async length => {
        await window.pipe.send(Uint8Array.from({ length }, (_, i) => i % 251));
      }, length);
      assert.equal(await received, true);
    }

    await a.evaluate(() => window.peer.close());
    assert.equal(await b.evaluate(() => window.pipe.recv()), null);
    console.log(
      `${name}: PASS offer/answer, isolated contexts, bidirectional 1 MiB frames, close`,
    );
  } finally {
    await browser.close();
  }
}
