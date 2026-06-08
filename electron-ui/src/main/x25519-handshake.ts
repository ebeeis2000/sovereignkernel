import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { X25519 } from './x25519';

const PROTO = 0x0001;
const CIPHER = 0x0001;
const MSG_CH = 0x01;
const MSG_SH = 0x02;
const MSG_CF = 0x03;
const MSG_SF = 0x04;

function validatePublicKey(pk: Buffer): boolean {
  if (pk.length !== 32) return false;
  let allZero = true;
  let lowOrder = true;
  for (let i = 0; i < 32; i++) {
    if (pk[i] !== 0) { allZero = false; }
  }
  if (allZero) return false;
  const lowOrderPoints = [
    Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
    Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex'),
    Buffer.from('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'),
    Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex'),
    Buffer.from('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157', 'hex'),
  ];
  for (const lop of lowOrderPoints) {
    if (pk.equals(lop)) return false;
  }
  return true;
}

class Transcript {
  private frames: Buffer[] = [];
  add(m: Buffer) { this.frames.push(Buffer.from(m)); }
  compute(): Buffer {
    const h = createHash('sha256');
    for (const f of this.frames) h.update(f);
    return h.digest();
  }
}

export class X25519Handshake {
  private transcript = new Transcript();

  buildClientHello() {
    const clientRandom = randomBytes(32);
    const { publicKey, privateKey } = X25519.generateKeyPair();
    if (!validatePublicKey(publicKey)) throw new Error('Invalid own public key');

    const supportedCiphers = Buffer.alloc(2);
    supportedCiphers.writeUInt16BE(CIPHER, 0);

    const message = Buffer.concat([
      Buffer.from([MSG_CH]),
      this.encodeVersion(),
      clientRandom,
      publicKey,
      supportedCiphers,
    ]);
    this.transcript.add(message);

    return { message, clientRandom, clientEphPub: publicKey, clientEphPriv: privateKey };
  }

  processServerHello(sh: Buffer) {
    if (sh.length < 85 || sh[0] !== MSG_SH) throw new Error('Invalid ServerHello');
    if (sh.readUInt16BE(1) !== PROTO) throw new Error('Protocol version mismatch');

    const serverRandom = sh.subarray(3, 35);
    const serverEphPub = sh.subarray(35, 67);
    const sessionId = sh.subarray(67, 83);
    const selectedCipher = sh.readUInt16BE(83);

    if (!validatePublicKey(serverEphPub)) throw new Error('Invalid server public key');
    if (selectedCipher !== CIPHER) throw new Error('Cipher mismatch');

    this.transcript.add(sh);
    return { serverRandom, serverEphPub, sessionId, selectedCipher };
  }

  deriveKeys(clientPriv: Buffer, serverPub: Buffer, clientRandom: Buffer, serverRandom: Buffer) {
    const sharedSecret = X25519.computeSharedSecret(clientPriv, serverPub);
    clientPriv.fill(0);

    const allZero = sharedSecret.every(b => b === 0);
    if (allZero) {
      sharedSecret.fill(0);
      throw new Error('X25519 shared secret is zero — mogelijke small-subgroup aanval');
    }

    const salt = Buffer.concat([clientRandom, serverRandom]);
    const masterKey = createHmac('sha256', salt).update(sharedSecret).digest();
    sharedSecret.fill(0);

    const encKey = Buffer.from(hkdfSync('sha256', masterKey, salt, 'SovereignKernel-IPC-encryption-v1', 32));
    const macKey = Buffer.from(hkdfSync('sha256', masterKey, salt, 'SovereignKernel-IPC-mac-v1', 32));

    return { masterKey, sessionKeys: { encKey, macKey } };
  }

  buildClientFinish(masterKey: Buffer): Buffer {
    const transcriptHash = this.transcript.compute();
    const verifyData = createHmac('sha256', masterKey).update(Buffer.from('client')).update(transcriptHash).digest();
    const message = Buffer.concat([Buffer.from([MSG_CF]), verifyData]);
    this.transcript.add(message);
    return message;
  }

  processServerFinish(sf: Buffer, masterKey: Buffer): boolean {
    if (sf.length < 33 || sf[0] !== MSG_SF) throw new Error('Invalid ServerFinish');
    const receivedVerify = sf.subarray(1, 33);

    const transcriptHash = this.transcript.compute();
    const expectedVerify = createHmac('sha256', masterKey).update(Buffer.from('server')).update(transcriptHash).digest();

    this.transcript.add(sf);

    return timingSafeEqual(receivedVerify, expectedVerify);
  }

  private encodeVersion(): Buffer {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(PROTO, 0);
    return b;
  }
}
