import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Factory } from '@muisit/cryptokey';
import { createKeyFromPem, pemToPrivateKeyHex } from './importKey';

const pemPath = fileURLToPath(new URL('./__fixtures__/test-key.pem', import.meta.url));
const pem = readFileSync(pemPath, 'utf8');

test('pemToPrivateKeyHex returns the 32-byte scalar of a P-256 PEM as hex', () => {
    const hex = pemToPrivateKeyHex(pem);
    assert.match(hex, /^[0-9a-f]{64}$/);
});

test('pemToPrivateKeyHex rejects a non-EC (RSA) PEM', () => {
    const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    assert.throws(() => pemToPrivateKeyHex(privateKey), /expected an EC key/);
});

test('createKeyFromPem yields a did:web document matching the PEM public key', async () => {
    const key = await createKeyFromPem('Secp256r1', pem);
    const doc = await Factory.toDIDDocument(key, 'did:web:example.com', null, 'JsonWebKey2020');
    const jwk = doc.verificationMethod![0].publicKeyJwk!;

    // The served publicKeyJwk must be an EC / P-256 key derived from the PEM.
    const expected = createPrivateKey(pem).export({ format: 'jwk' });
    assert.equal(jwk.kty, 'EC');
    assert.equal(jwk.crv, 'P-256');
    assert.equal(jwk.x, expected.x);
    assert.equal(jwk.y, expected.y);
});

test('importing the same PEM twice yields the same public key (stable identity)', async () => {
    const first = await createKeyFromPem('Secp256r1', pem);
    const second = await createKeyFromPem('Secp256r1', pem);
    const docOf = async (k: Awaited<ReturnType<typeof createKeyFromPem>>) =>
        (await Factory.toDIDDocument(k, 'did:web:example.com', null, 'JsonWebKey2020'))
            .verificationMethod![0].publicKeyJwk;
    assert.deepEqual(await docOf(first), await docOf(second));
});
