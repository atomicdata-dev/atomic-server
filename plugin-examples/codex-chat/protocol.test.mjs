import test from 'node:test';
import assert from 'node:assert/strict';
import { Codex } from './protocol.mjs';
const fake = `const r=require('node:readline').createInterface({input:process.stdin});r.on('line',l=>{const m=JSON.parse(l);if(m.method==='fail')process.stdout.write(JSON.stringify({id:m.id,error:{message:'denied'}})+'\\n');else if(m.id)process.stdout.write(JSON.stringify({id:m.id,result:{method:m.method}})+'\\n');});`;
test('stdio correlates concurrent replies and propagates RPC errors', async () => {
  const c = new Codex(process.execPath, ['-e', fake]);
  try {
    await c.initialize();
    const replies = await Promise.all([c.request('one'), c.request('two')]);
    assert.deepEqual(replies, [{ method: 'one' }, { method: 'two' }]);
    await assert.rejects(c.request('fail'), /denied/);
  } finally {
    c.close();
  }
});
test('process exit rejects outstanding RPC instead of hanging', async () => {
  const c = new Codex(process.execPath, ['-e', 'process.exit(0)']);
  await assert.rejects(c.request('one'), /exited|closed/);
});
