import { createECDH, randomBytes } from 'node:crypto';

export class X25519 {
  static generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
    const ecdh = createECDH('x25519');
    ecdh.generateKeys();
    return {
      publicKey: ecdh.getPublicKey() as Buffer,
      privateKey: ecdh.getPrivateKey() as Buffer,
    };
  }

  static computeSharedSecret(privateKey: Buffer, publicKey: Buffer): Buffer {
    const ecdh = createECDH('x25519');
    ecdh.setPrivateKey(privateKey);
    return ecdh.computeSecret(publicKey) as Buffer;
  }
}
