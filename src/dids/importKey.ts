import { createPrivateKey } from 'node:crypto';
import { CryptoKey, Factory } from '@muisit/cryptokey';

/**
 * Extract the raw private-key scalar (hex encoded) from a PEM-encoded EC
 * private key, in the form Factory.createFromType expects.
 *
 * Supports the P-256 curve used by the Secp256r1 key type. The PEM may be in
 * PKCS#8 (`BEGIN PRIVATE KEY`) or SEC1 (`BEGIN EC PRIVATE KEY`) form; both are
 * understood by node's crypto.
 */
export function pemToPrivateKeyHex(pem: string): string {
    const jwk = createPrivateKey(pem).export({ format: 'jwk' });
    if (jwk.kty !== 'EC') {
        throw new Error(`Unsupported key type "${jwk.kty}" in PEM, expected an EC key`);
    }
    if (!jwk.d) {
        throw new Error('PEM does not contain a private key (no "d" component)');
    }
    return CryptoKey.bytesToHex(CryptoKey.base64UrlToBytes(jwk.d));
}

/**
 * Build a CryptoKey of the given type from a PEM-encoded private key. The
 * resulting key is deterministic in the PEM, so the derived did:web / did:jwk
 * identity stays constant across restarts and fresh deployments.
 */
export function createKeyFromPem(keyType: string, pem: string): Promise<CryptoKey> {
    return Factory.createFromType(keyType, pemToPrivateKeyHex(pem));
}
