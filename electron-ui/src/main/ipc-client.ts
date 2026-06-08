import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { connect } from 'node:net';
import { EventEmitter } from 'node:events';
import { X25519Handshake } from './x25519-handshake';

const PIPE = '\\\\.\\pipe\\SovereignKernelVault';
const HEARTBEAT_INTERVAL = 30000;
const TIMEOUT = 300000;
const MAX_RECONNECT = 5;
const MAX_MESSAGE_SIZE = 1024 * 1024;

export class IpcClient extends EventEmitter {
  private sock: ReturnType<typeof connect> | null = null;
  private keys: { encKey: Buffer; macKey: Buffer } | null = null;
  private clientSeq: bigint = 0n;
  private serverSeq: bigint = 0n;
  private pending = new Map<bigint, { resolve: (v: Buffer) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private timeoutTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectCount = 0;
  private _connected = false;
  private recvBuffer = Buffer.alloc(0);

  constructor() {
    super();
  }

  get connected(): boolean { return this._connected; }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.sock = connect(PIPE);

      this.sock.on('connect', async () => {
        try {
          await this.performHandshake();
          this._connected = true;
          this.reconnectCount = 0;
          this.startHeartbeat();
          this.emit('connected');
          resolve();
        } catch (err) {
          reject(err);
        }
      });

      this.sock.on('error', (err) => {
        this.emit('error', err);
        if (!this._connected) reject(err);
      });

      this.sock.on('close', () => {
        this._connected = false;
        this.stopHeartbeat();
        this.emit('disconnected');
        this.attemptReconnect();
      });

      this.sock.on('data', (data: Buffer) => {
        this.onData(data);
      });
    });
  }

  async send(command: string, payload?: Record<string, unknown>): Promise<Buffer> {
    if (!this._connected || !this.keys) {
      throw new Error('Niet verbonden met vault service');
    }

    const seq = this.clientSeq++;
    const msg = Buffer.from(JSON.stringify({ seq: seq.toString(), command, ...payload }));
    const encrypted = this.encrypt(msg);
    const framed = this.frameMessage(encrypted);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(seq);
        reject(new Error(`Timeout voor commando: ${command}`));
      }, 30000);

      this.pending.set(seq, { resolve, reject, timer });
      this.sock!.write(framed);
    });
  }

  disconnect(): void {
    this.stopHeartbeat();
    if (this.sock) {
      this.sock.destroy();
      this.sock = null;
    }
    this._connected = false;
    this.keys = null;
    this.recvBuffer = Buffer.alloc(0);
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error('Verbinding verbroken'));
    }
    this.pending.clear();
  }

  private frameMessage(data: Buffer): Buffer {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(data.length, 0);
    return Buffer.concat([header, data]);
  }

  private onData(chunk: Buffer): void {
    this.recvBuffer = Buffer.concat([this.recvBuffer, chunk]);
    while (this.recvBuffer.length >= 4) {
      const msgLen = this.recvBuffer.readUInt32BE(0);
      if (msgLen > MAX_MESSAGE_SIZE) {
        this.emit('error', new Error('Bericht te groot — mogelijke aanval'));
        this.disconnect();
        return;
      }
      if (this.recvBuffer.length < 4 + msgLen) break;
      const msg = this.recvBuffer.subarray(4, 4 + msgLen);
      this.recvBuffer = this.recvBuffer.subarray(4 + msgLen);
      this.handleIncoming(Buffer.from(msg));
    }
  }

  private async performHandshake(): Promise<void> {
    const handshake = new X25519Handshake();
    const ch = handshake.buildClientHello();
    this.sock!.write(ch.message);

    const sh = await this.readMessage();
    const serverHello = handshake.processServerHello(sh);
    const { masterKey, sessionKeys } = handshake.deriveKeys(
      ch.clientEphPriv, serverHello.serverEphPub, ch.clientRandom, serverHello.serverRandom
    );

    const cf = handshake.buildClientFinish(masterKey);
    this.sock!.write(cf);

    const sf = await this.readMessage();
    if (!handshake.processServerFinish(sf, masterKey)) {
      throw new Error('Server authenticatie mislukt');
    }

    this.keys = sessionKeys;
    masterKey.fill(0);
  }

  private readMessage(): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Handshake timeout')), 10000);
      this.sock!.once('data', (data: Buffer) => {
        clearTimeout(timeout);
        resolve(data);
      });
    });
  }

  private handleIncoming(data: Buffer): void {
    if (!this.keys) return;
    try {
      const decrypted = this.decrypt(data);
      const msg = JSON.parse(decrypted.toString());
      const seq = BigInt(msg.seq);

      if (seq < this.serverSeq) {
        this.emit('error', new Error('Replay gedetecteerd: sequence nummer te laag'));
        return;
      }

      const pending = this.pending.get(seq);
      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(seq);
        pending.resolve(decrypted);
      }
      this.serverSeq = seq + 1n;
      this.resetTimeout();
    } catch {
      this.emit('error', new Error('Ongeldig bericht ontvangen'));
    }
  }

  private encrypt(plaintext: Buffer): Buffer {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.keys!.encKey, nonce);
    cipher.setAAD(Buffer.from(this.clientSeq.toString()));
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, encrypted, tag]);
  }

  private decrypt(data: Buffer): Buffer {
    if (data.length < 28) throw new Error('Data te kort');
    const nonce = data.subarray(0, 12);
    const tag = data.subarray(data.length - 16);
    const ciphertext = data.subarray(12, data.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', this.keys!.encKey, nonce);
    decipher.setAAD(Buffer.from(this.serverSeq.toString()));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      if (this._connected) {
        this.send('heartbeat').catch(() => {});
      }
    }, HEARTBEAT_INTERVAL);

    this.resetTimeout();
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) { clearInterval(this.heartbeatTimer); this.heartbeatTimer = null; }
    if (this.timeoutTimer) { clearTimeout(this.timeoutTimer); this.timeoutTimer = null; }
  }

  private resetTimeout(): void {
    if (this.timeoutTimer) clearTimeout(this.timeoutTimer);
    this.timeoutTimer = setTimeout(() => {
      this.emit('timeout');
      this.disconnect();
    }, TIMEOUT);
  }

  private attemptReconnect(): void {
    if (this.reconnectCount >= MAX_RECONNECT) {
      this.emit('max_reconnect');
      return;
    }
    this.reconnectCount++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectCount), 30000);
    setTimeout(() => this.connect().catch(() => {}), delay);
  }
}
