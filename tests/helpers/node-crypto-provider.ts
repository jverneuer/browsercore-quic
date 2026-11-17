/**
 * Test-only CryptoProvider backed by Node's native `node:crypto`.
 *
 * Production code must never import `node:*` — crypto is injected through
 * Platform. Tests run on Node CI, so they may build a real provider here and
 * thread it through the code under test. This helper stands in for the
 * `@browsercore/crypto` singleton that was removed in 0.2.2.
 *
 * It implements only the primitives the QUIC unit tests exercise (randomness,
 * hashing, HKDF, HMAC, AES-GCM, ChaCha20-Poly1305, AES-ECB). The asymmetric
 * methods (X25519, ECDH, ML-KEM, signature verification) are not touched by
 * these tests, so they throw rather than ship an out-of-scope implementation.
 */

import {
    randomBytes as nodeRandomBytes,
    createHash,
    createHmac,
    hkdfSync,
    createCipheriv,
    createDecipheriv,
    type CipherGCM,
    type DecipherGCM,
} from "node:crypto";
import type { CryptoProvider, HashId } from "@browsercore/contracts";

/**
 * Run a node:crypto AEAD cipher over `data` with the given AAD, returning a
 * standalone copy (node returns Buffers that may view an internal pool).
 *
 * Every caller uses an AEAD mode (GCM or ChaCha20-Poly1305), which node types
 * as `CipherGCM`/`DecipherGCM` — those carry `setAAD`/`update`/`final`.
 */
function runAead(cipher: CipherGCM | DecipherGCM, data: Uint8Array, aad: Uint8Array): Uint8Array {
    cipher.setAAD(aad, { plaintextLength: data.length });
    const out = new Uint8Array(cipher.update(data));
    const final = new Uint8Array(cipher.final());
    const result = new Uint8Array(out.length + final.length);
    result.set(out, 0);
    result.set(final, out.length);
    return result;
}

function hashAlgorithmName(hash: HashId): "sha256" | "sha384" {
    // oxlint-disable-next-line typescript/switch-exhaustiveness-check -- RangeError guard for new HashId members
    switch (hash) {
        case "SHA-256":
            return "sha256";
        case "SHA-384":
            return "sha384";
        default:
            throw new RangeError(`unsupported hash: ${hash}`);
    }
}

/** AEAD tag length for GCM / ChaCha20-Poly1305 (bytes). */
const AEAD_TAG_LENGTH = 16;

function aesGcmAlgorithm(key: Uint8Array): "aes-128-gcm" | "aes-256-gcm" {
    return key.length === 16 ? "aes-128-gcm" : "aes-256-gcm";
}

/** AES-GCM encrypt: returns ciphertext with the 16-byte auth tag appended. */
function aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
    const enc = createCipheriv(aesGcmAlgorithm(key), key, nonce);
    const body = runAead(enc, plaintext, aad);
    const tag = new Uint8Array(enc.getAuthTag());
    const result = new Uint8Array(body.length + tag.length);
    result.set(body, 0);
    result.set(tag, body.length);
    return result;
}

/** AES-GCM decrypt: expects ciphertext with the 16-byte auth tag appended. */
function aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertextAndTag: Uint8Array, aad: Uint8Array): Uint8Array {
    const tagStart = ciphertextAndTag.length - AEAD_TAG_LENGTH;
    const ciphertext = ciphertextAndTag.subarray(0, tagStart);
    const tag = ciphertextAndTag.subarray(tagStart);
    const dec = createDecipheriv(aesGcmAlgorithm(key), key, nonce);
    dec.setAuthTag(tag);
    return runAead(dec, ciphertext, aad);
}

/** A minimal CryptoProvider sufficient for the QUIC unit tests. */
export const nodeCrypto: CryptoProvider = {
    randomBytes(length: number): Uint8Array {
        return nodeRandomBytes(length);
    },
    sha256(data: Uint8Array): Uint8Array {
        return new Uint8Array(createHash("sha256").update(data).digest());
    },
    sha384(data: Uint8Array): Uint8Array {
        return new Uint8Array(createHash("sha384").update(data).digest());
    },
    hkdf(hash, salt, ikm, info, length): Uint8Array {
        const digest = hashAlgorithmName(hash);
        return new Uint8Array(hkdfSync(digest, ikm, salt, info, length));
    },
    hmac(hash, key, data): Uint8Array {
        const digest = hashAlgorithmName(hash);
        return new Uint8Array(createHmac(digest, key).update(data).digest());
    },
    aes128GcmEncrypt(key, nonce, plaintext, aad): Uint8Array {
        return aesGcmEncrypt(key, nonce, plaintext, aad);
    },
    aes128GcmDecrypt(key, nonce, ciphertext, aad): Uint8Array {
        return aesGcmDecrypt(key, nonce, ciphertext, aad);
    },
    aes256GcmEncrypt(key, nonce, plaintext, aad): Uint8Array {
        return aesGcmEncrypt(key, nonce, plaintext, aad);
    },
    aes256GcmDecrypt(key, nonce, ciphertext, aad): Uint8Array {
        return aesGcmDecrypt(key, nonce, ciphertext, aad);
    },
    aes128CcmEncrypt(_key, _nonce, _plaintext, _aad): Uint8Array {
        throw new Error("AES-128-CCM not supported by test crypto provider");
    },
    aes128CcmDecrypt(_key, _nonce, _ciphertext, _aad): Uint8Array {
        throw new Error("AES-128-CCM not supported by test crypto provider");
    },
    chacha20Poly1305Encrypt(key, nonce, plaintext, aad): Uint8Array {
        const enc = createCipheriv("chacha20-poly1305", key, nonce);
        const body = runAead(enc, plaintext, aad);
        const tag = new Uint8Array(enc.getAuthTag());
        const result = new Uint8Array(body.length + tag.length);
        result.set(body, 0);
        result.set(tag, body.length);
        return result;
    },
    chacha20Poly1305Decrypt(key, nonce, ciphertext, aad): Uint8Array {
        const tagStart = ciphertext.length - AEAD_TAG_LENGTH;
        const data = ciphertext.subarray(0, tagStart);
        const tag = ciphertext.subarray(tagStart);
        const dec = createDecipheriv("chacha20-poly1305", key, nonce);
        dec.setAuthTag(tag);
        return runAead(dec, data, aad);
    },
    x25519GenerateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
        throw new Error("x25519GenerateKeyPair not supported by test crypto provider");
    },
    x25519SharedSecret(_secretKey, _peerPublicKey): Uint8Array {
        throw new Error("x25519SharedSecret not supported by test crypto provider");
    },
    ecdhGenerateKeyPair(_curve): { curve: "secp256r1"; publicKey: Uint8Array; secretKey: Uint8Array } {
        throw new Error("ecdhGenerateKeyPair not supported by test crypto provider");
    },
    ecdhSharedSecret(_curve, _secretKey, _peerPublicKey): Uint8Array {
        throw new Error("ecdhSharedSecret not supported by test crypto provider");
    },
    verifySignature(_scheme, _publicKey, _signature, _data): boolean {
        throw new Error("verifySignature not supported by test crypto provider");
    },
    aesEcbEncrypt(key, block): Uint8Array {
        const algorithm = key.length === 16 ? "aes-128-ecb" : "aes-256-ecb";
        const cipher = createCipheriv(algorithm, key, new Uint8Array(0));
        cipher.setAutoPadding(false);
        const out = new Uint8Array(cipher.update(block));
        const final = new Uint8Array(cipher.final());
        const result = new Uint8Array(out.length + final.length);
        result.set(out, 0);
        result.set(final, out.length);
        return result;
    },
    // ML-KEM (FIPS 203) joined the canonical CryptoProvider surface with the
    // X25519MLKEM768 key exchange. The QUIC unit tests never run a real TLS
    // handshake against this provider (the handshake is mocked or an engine is
    // injected), so — matching the x25519/ecdh stubs above — these throw
    // rather than ship an out-of-scope implementation.
    mlkem768GenerateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
        throw new Error("mlkem768GenerateKeyPair not supported by test crypto provider");
    },
    mlkem768Decapsulate(_secretKey, _ciphertext): Uint8Array {
        throw new Error("mlkem768Decapsulate not supported by test crypto provider");
    },
    x25519MLKEM768SharedSecret(_x25519SecretKey, _x25519PeerPublicKey, _mlkemSecretKey, _mlkemCiphertext): Uint8Array {
        throw new Error("x25519MLKEM768SharedSecret not supported by test crypto provider");
    },
};
