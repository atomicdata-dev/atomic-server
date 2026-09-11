/** Reliable, ordered Atomic frame transport. Authentication belongs to the sync
 * session: an open data channel is never evidence of drive access. */
export class WebRtcTransport {
  private readonly pending: Uint8Array[] = [];
  private readonly readers: Array<{
    resolve: (frame: Uint8Array | null) => void;
    reject: (error: Error) => void;
  }> = [];
  private queuedBytes = 0;
  private sendingBytes = 0;
  private partial?: Uint8Array;
  private offset = 0;
  private ended = false;
  private failure?: Error;
  private sending: Promise<void> = Promise.resolve();
  private readonly cancellations = new Set<(error: Error) => void>();

  constructor(
    private readonly channel: RTCDataChannel,
    private readonly maxMessageSize: () => number = () => 16 * 1024,
    private readonly maxFrameBytes: number = 16 * 1024 * 1024,
  ) {
    if (
      !channel.ordered ||
      channel.maxRetransmits !== null ||
      channel.maxPacketLifeTime !== null
    ) {
      throw new Error('Atomic sync requires an ordered, reliable data channel');
    }

    if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 1) {
      throw new Error('Invalid Atomic frame budget');
    }

    channel.binaryType = 'arraybuffer';
    channel.bufferedAmountLowThreshold = 64 * 1024;
    channel.addEventListener('message', this.onMessage);
    channel.addEventListener('close', this.onClose);
    channel.addEventListener('error', this.onError);
  }

  /** Frames are length-prefixed and fragmented below SCTP's negotiated limit. */
  send(frame: Uint8Array): Promise<void> {
    if (frame.length === 0 || frame.length > this.maxFrameBytes) {
      return Promise.reject(new Error('Invalid Atomic frame size'));
    }

    if (this.ended)
      return Promise.reject(
        this.failure ?? new Error('WebRTC transport closed'),
      );

    if (this.sendingBytes + frame.length > this.maxFrameBytes) {
      return Promise.reject(new Error('Atomic send queue full'));
    }

    this.sendingBytes += frame.length;
    // Snapshot before queuing: callers may reuse their encoding buffer.
    const copy = frame.slice();
    const operation = this.sending
      .then(() => this.write(copy))
      .finally(() => {
        this.sendingBytes -= copy.length;
      });
    this.sending = operation.catch(() => {});

    return operation;
  }

  recv(): Promise<Uint8Array | null> {
    const frame = this.pending.shift();

    if (frame) {
      this.queuedBytes -= frame.length;

      return Promise.resolve(frame);
    }

    if (this.failure) return Promise.reject(this.failure);
    if (this.ended) return Promise.resolve(null);

    return new Promise((resolve, reject) =>
      this.readers.push({ resolve, reject }),
    );
  }

  close(): void {
    this.finish();
  }

  private async write(frame: Uint8Array): Promise<void> {
    const wire = new Uint8Array(frame.length + 4);
    new DataView(wire.buffer).setUint32(0, frame.length);
    wire.set(frame, 4);
    const negotiated = this.maxMessageSize();
    // Zero means unlimited in RTCSctpTransport; use conservative chunks anyway.
    const size = Math.min(16 * 1024, negotiated || 16 * 1024);
    if (!Number.isInteger(size) || size < 4)
      throw new Error('Invalid SCTP message size');

    try {
      for (let offset = 0; offset < wire.length; offset += size) {
        if (this.ended)
          throw this.failure ?? new Error('WebRTC transport closed');
        if (this.channel.readyState !== 'open')
          throw new Error('WebRTC channel is not open');
        if (this.channel.bufferedAmount > 128 * 1024)
          await this.waitForBuffer();
        this.channel.send(wire.slice(offset, offset + size).buffer);
      }
    } catch (error) {
      // A partial frame cannot be retried on this stream without corrupting it.
      this.finish(error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  private waitForBuffer(): Promise<void> {
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        this.channel.removeEventListener('bufferedamountlow', ready);
        this.cancellations.delete(cancel);
      };

      const ready = () => {
        cleanup();
        resolve();
      };

      const cancel = (error: Error) => {
        cleanup();
        reject(error);
      };

      this.cancellations.add(cancel);
      this.channel.addEventListener('bufferedamountlow', ready);
      if (this.ended)
        cancel(this.failure ?? new Error('WebRTC transport closed'));
      else if (
        this.channel.bufferedAmount <= this.channel.bufferedAmountLowThreshold
      )
        ready();
    });
  }

  private readonly onMessage = (event: MessageEvent): void => {
    if (this.ended) return;

    try {
      if (!(event.data instanceof ArrayBuffer))
        throw new Error('Expected binary Atomic frame');
      const bytes = new Uint8Array(event.data);
      let start = 0;

      if (!this.partial) {
        if (bytes.length < 4) throw new Error('Missing Atomic frame length');
        const length = new DataView(bytes.buffer).getUint32(0);
        if (!length || length > this.maxFrameBytes)
          throw new Error('Invalid Atomic frame size');
        if (length + this.queuedBytes > this.maxFrameBytes)
          throw new Error('Atomic receive queue full');
        this.partial = new Uint8Array(length);
        this.offset = 0;
        start = 4;
      }

      if (bytes.length - start > this.partial.length - this.offset)
        throw new Error('Atomic frame overflow');
      this.partial.set(bytes.subarray(start), this.offset);
      this.offset += bytes.length - start;

      if (this.offset === this.partial.length) {
        const frame = this.partial;
        this.partial = undefined;
        const reader = this.readers.shift();

        if (reader) reader.resolve(frame);
        else {
          this.pending.push(frame);
          this.queuedBytes += frame.length;
        }
      }
    } catch (error) {
      this.finish(error instanceof Error ? error : new Error(String(error)));
    }
  };

  private readonly onClose = (): void => {
    this.finish(this.partial ? new Error('Truncated Atomic frame') : undefined);
  };
  private readonly onError = (): void => {
    this.finish(new Error('WebRTC data channel failed'));
  };

  private finish(error?: Error): void {
    if (this.ended) return;
    this.ended = true;
    this.failure = error;
    this.partial = undefined;
    this.channel.removeEventListener('message', this.onMessage);
    this.channel.removeEventListener('close', this.onClose);
    this.channel.removeEventListener('error', this.onError);
    for (const cancel of this.cancellations)
      cancel(error ?? new Error('WebRTC transport closed'));

    for (const reader of this.readers.splice(0)) {
      if (error) reader.reject(error);
      else reader.resolve(null);
    }

    if (error) {
      this.pending.length = 0;
      this.queuedBytes = 0;
    }

    this.channel.close();
  }
}
