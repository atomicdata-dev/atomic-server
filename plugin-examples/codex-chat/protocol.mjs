import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { EventEmitter } from 'node:events';

/** Dedicated stdio process: no browser-facing shell or unauthenticated socket. */
export class Codex extends EventEmitter {
  constructor(
    command = process.env.CODEX_BIN || 'codex',
    args = ['app-server', '--stdio'],
  ) {
    super();
    this.pending = new Map();
    this.nextId = 0;
    this.child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    // Drain diagnostics; never copy environment or raw protocol into the UI.
    this.child.stderr.resume();
    createInterface({ input: this.child.stdout }).on('line', line => {
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        return;
      }
      if (message.method) this.emit('message', message);
      else {
        const call = this.pending.get(message.id);
        if (!call) return;
        this.pending.delete(message.id);
        clearTimeout(call.timer);
        if (message.error) call.reject(new Error(message.error.message));
        else call.resolve(message.result);
      }
    });
    const fail = error => {
      this.closed = true;
      for (const call of this.pending.values()) {
        clearTimeout(call.timer);
        call.reject(error);
      }
      this.pending.clear();
      this.emit('closed', error);
    };
    this.child.on('error', fail);
    this.child.on('exit', () => fail(new Error('Codex app-server exited')));
    this.child.stdin.on('error', () => {});
  }
  send(message) {
    if (this.closed) throw new Error('Codex app-server is closed');
    this.child.stdin.write(JSON.stringify(message) + '\n');
  }
  request(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++this.nextId;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out; its outcome may be uncertain`));
      }, 30000);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.send({ id, method, params });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
  }
  async initialize() {
    await this.request('initialize', {
      clientInfo: {
        name: 'atomic_codex_chat',
        title: 'Atomic Codex Chat',
        version: '0.1.0',
      },
      capabilities: { experimentalApi: false },
    });
    this.send({ method: 'initialized' });
  }
  close() {
    this.child.kill();
  }
}
