import { WebRtcTransport } from './webrtc-transport.js';

const PROTOCOL = 'atomic-sync-v2-framed-v1';

/** Explicit, non-trickle offer/answer pairing. Exchange the returned SDP through
 * a user-selected signaling channel. This establishes transport, not authority. */
export class WebRtcPeer {
  readonly transport: Promise<WebRtcTransport>;
  private readonly connection: RTCPeerConnection;
  private resolve!: (transport: WebRtcTransport) => void;
  private reject!: (error: Error) => void;
  private channel?: RTCDataChannel;
  private pipe?: WebRtcTransport;
  private closed = false;
  private readonly timer: ReturnType<typeof setTimeout>;
  private readonly cancelGathering = new Set<() => void>();

  constructor(configuration: RTCConfiguration = {}, timeoutMs = 60_000) {
    this.connection = new RTCPeerConnection(configuration);
    this.transport = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
    // Pairing can fail while the caller is still exchanging SDP.
    void this.transport.catch(() => {});
    this.timer = setTimeout(
      () => this.close(new Error('WebRTC pairing timed out')),
      timeoutMs,
    );
    this.connection.addEventListener('datachannel', event =>
      this.attach(event.channel),
    );
    this.connection.addEventListener('connectionstatechange', () => {
      if (
        this.connection.connectionState === 'failed' ||
        this.connection.connectionState === 'closed'
      ) {
        this.close(new Error('WebRTC connection closed'));
      }
    });
  }

  async createOffer(): Promise<RTCSessionDescriptionInit> {
    this.attach(
      this.connection.createDataChannel('atomic-sync', {
        ordered: true,
        protocol: PROTOCOL,
      }),
    );

    return this.localDescription(await this.connection.createOffer());
  }

  async acceptOffer(
    offer: RTCSessionDescriptionInit,
  ): Promise<RTCSessionDescriptionInit> {
    if (offer.type !== 'offer') throw new Error('Expected a WebRTC offer');
    await this.connection.setRemoteDescription(offer);

    return this.localDescription(await this.connection.createAnswer());
  }

  async acceptAnswer(answer: RTCSessionDescriptionInit): Promise<void> {
    if (answer.type !== 'answer') throw new Error('Expected a WebRTC answer');
    await this.connection.setRemoteDescription(answer);
  }

  /** Bind Atomic authentication to both DTLS certificates, independently of signaling. */
  async channelBinding(): Promise<string> {
    const fingerprints = [
      this.connection.localDescription?.sdp,
      this.connection.remoteDescription?.sdp,
    ]
      .map(sdp => {
        const values = [...(sdp ?? '').matchAll(/^a=fingerprint:(.+)$/gm)].map(
          match => match[1].trim(),
        );
        if (!values.length)
          throw new Error('Missing WebRTC certificate fingerprint');

        return [...new Set(values)].sort().join(',');
      })
      .sort()
      .join('|');
    const hash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(fingerprints),
    );

    return Array.from(new Uint8Array(hash), byte =>
      byte.toString(16).padStart(2, '0'),
    ).join('');
  }

  async connectionPath(): Promise<'direct' | 'relayed' | 'unknown'> {
    const stats = await this.connection.getStats();

    for (const report of stats.values()) {
      if (
        report.type === 'candidate-pair' &&
        report.state === 'succeeded' &&
        report.nominated
      ) {
        const local = stats.get(report.localCandidateId);
        const remote = stats.get(report.remoteCandidateId);

        return local?.candidateType === 'relay' ||
          remote?.candidateType === 'relay'
          ? 'relayed'
          : 'direct';
      }
    }

    return 'unknown';
  }

  close(error = new Error('WebRTC peer closed')): void {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.timer);
    for (const cancel of this.cancelGathering) cancel();
    this.reject(error);
    this.pipe?.close();
    this.channel?.close();
    this.connection.close();
  }

  private attach(channel: RTCDataChannel): void {
    if (this.channel || this.closed || channel.protocol !== PROTOCOL) {
      channel.close();
      this.close(new Error('Unexpected WebRTC data channel'));

      return;
    }

    this.channel = channel;
    channel.addEventListener('close', () => queueMicrotask(() => this.close()));
    channel.addEventListener('error', () =>
      this.close(new Error('WebRTC data channel failed')),
    );
    channel.addEventListener(
      'open',
      () => {
        if (this.closed) return;

        try {
          this.pipe = new WebRtcTransport(
            channel,
            () => this.connection.sctp?.maxMessageSize ?? 16 * 1024,
          );
          clearTimeout(this.timer);
          this.resolve(this.pipe);
        } catch (error) {
          this.close(error instanceof Error ? error : new Error(String(error)));
        }
      },
      { once: true },
    );
  }

  private async localDescription(
    description: RTCSessionDescriptionInit,
  ): Promise<RTCSessionDescriptionInit> {
    await this.connection.setLocalDescription(description);
    await new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        this.connection.removeEventListener('icegatheringstatechange', check);
        this.cancelGathering.delete(cancel);
      };

      const cancel = () => {
        cleanup();
        reject(new Error('WebRTC pairing closed'));
      };

      const check = () => {
        if (this.closed) cancel();
        else if (this.connection.iceGatheringState === 'complete') {
          cleanup();
          resolve();
        }
      };

      this.cancelGathering.add(cancel);
      this.connection.addEventListener('icegatheringstatechange', check);
      check();
    });
    const local = this.connection.localDescription;
    if (!local) throw new Error('Missing WebRTC local description');

    return { type: local.type, sdp: local.sdp };
  }
}
