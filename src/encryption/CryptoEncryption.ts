import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoCipher } from "./CryptoCipher";
import { CryptoSecretKey } from "./CryptoSecretKey";

/**
 * The symmetric encryption algorithm to use.
 */
export const enum CryptoEncryptionAlgorithm {
    /**
     * AES 128-bit encryption with Galois-Counter-Mode
     * 12-byte Initialization Vector is prepended to cipher
     * 16-byte Authentication Tag is appended to cipher
     */
    // eslint-disable-next-line @typescript-eslint/naming-convention
    AES128_GCM = 1,
    /**
     * AES 256-bit encryption with Galois-Counter-Mode
     * 12-byte Initialization Vector is prepended to cipher
     * 16-byte Authentication Tag is appended to cipher
     */
    // eslint-disable-next-line @typescript-eslint/naming-convention
    AES256_GCM = 2,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    XCHACHA20_POLY1305 = 3
}

export abstract class CryptoEncryption {
    public static async generateKey(
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoSecretKey> {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);

        let buffer: CoreBuffer;
        switch (algorithm) {
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                try {
                    buffer = new CoreBuffer((await SodiumWrapper.ready()).crypto_aead_xchacha20poly1305_ietf_keygen());
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.EncryptionKeyGeneration, `${e}`);
                }

                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }

        return CryptoSecretKey.from({ secretKey: buffer, algorithm });
    }

    /**
     * Encrypts a given plaintext [[CoreBuffer]] object with the given secretKey. If a nonce is set,
     * please be advised that this nonce MUST be uniquely used for this secretKey. The nonce MUST be
     * a high entropy (best random) [[CoreBuffer]] object.
     *
     * @param plaintext
     * @param secretKey
     * @param nonce
     * @param algorithm
     */
    public static async encrypt(
        plaintext: CoreBuffer,
        secretKey: CryptoSecretKey | CoreBuffer,
        nonce?: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoCipher> {
        let correctAlgorithm;
        let secretKeyBuffer;

        if (secretKey instanceof CryptoSecretKey) {
            correctAlgorithm = secretKey.algorithm;
            secretKeyBuffer = secretKey.secretKey.buffer;
        } else if (secretKey instanceof CoreBuffer) {
            CryptoValidation.checkEncryptionAlgorithm(algorithm);

            correctAlgorithm = algorithm;

            CryptoValidation.checkSecretKeyForAlgorithm(secretKey, correctAlgorithm);

            secretKeyBuffer = secretKey.buffer;
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongSecretKey,
                "Secret key must either be a CoreBuffer or a CryptoSecretKey object."
            );
        }

        const sodium = await SodiumWrapper.ready();

        let publicnonce: Uint8Array;
        if (typeof nonce !== "undefined") {
            CryptoValidation.checkNonceForAlgorithm(nonce, correctAlgorithm);
            publicnonce = nonce.buffer;
        } else {
            publicnonce = sodium.randombytes_buf(24);
        }

        let cipher: Uint8Array;
        switch (correctAlgorithm) {
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                try {
                    cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                        plaintext.buffer,
                        "",
                        new Uint8Array(),
                        publicnonce,
                        secretKeyBuffer
                    );
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`);
                }
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }

        return CryptoCipher.from({
            cipher: CoreBuffer.from(cipher),
            algorithm: correctAlgorithm,
            nonce: CoreBuffer.from(publicnonce)
        });
    }

    public static async encryptWithCounter(
        plaintext: CoreBuffer,
        secretKey: CryptoSecretKey | CoreBuffer,
        nonce: CoreBuffer,
        counter: number,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoCipher> {
        let correctAlgorithm;
        let secretKeyBuffer;
        if (secretKey instanceof CryptoSecretKey) {
            correctAlgorithm = secretKey.algorithm;
            secretKeyBuffer = secretKey.secretKey.buffer;
        } else if (secretKey instanceof CoreBuffer) {
            CryptoValidation.checkEncryptionAlgorithm(algorithm);
            correctAlgorithm = algorithm;

            CryptoValidation.checkSecretKeyForAlgorithm(secretKey, correctAlgorithm);
            secretKeyBuffer = secretKey.buffer;
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongSecretKey,
                "Secret key must either be a CoreBuffer or a CryptoSecretKey object."
            );
        }

        CryptoValidation.checkCounter(counter);

        const publicnonce = this._addCounter(nonce.buffer, counter);

        let cipherbuffer: CoreBuffer;
        switch (algorithm) {
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                try {
                    const cipher = (await SodiumWrapper.ready()).crypto_aead_xchacha20poly1305_ietf_encrypt(
                        plaintext.buffer,
                        "",
                        new Uint8Array(),
                        publicnonce.buffer,
                        secretKeyBuffer
                    );
                    cipherbuffer = new CoreBuffer(cipher);
                    return CryptoCipher.from({ cipher: cipherbuffer, algorithm, counter });
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`);
                }
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }
    }

    public static async decrypt(
        cipher: CryptoCipher,
        secretKey: CryptoSecretKey | CoreBuffer,
        nonce?: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CoreBuffer> {
        let correctAlgorithm;
        let secretKeyBuffer;

        if (secretKey instanceof CryptoSecretKey) {
            correctAlgorithm = secretKey.algorithm;
            secretKeyBuffer = secretKey.secretKey.buffer;
        } else if (secretKey instanceof CoreBuffer) {
            CryptoValidation.checkEncryptionAlgorithm(algorithm);
            correctAlgorithm = algorithm;

            CryptoValidation.checkSecretKeyForAlgorithm(secretKey, correctAlgorithm);
            secretKeyBuffer = secretKey.buffer;
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongSecretKey,
                "Secret key must either be a CoreBuffer or a CryptoSecretKey object."
            );
        }

        let publicnonce;
        if (typeof nonce !== "undefined") {
            CryptoValidation.checkNonceForAlgorithm(nonce, correctAlgorithm);
            publicnonce = nonce.buffer;
        } else if (typeof cipher !== "undefined" && typeof cipher.nonce !== "undefined") {
            publicnonce = cipher.nonce.buffer;
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongNonce,
                "Cipher does not contain a nonce and no nonce is given."
            );
        }

        switch (correctAlgorithm) {
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                try {
                    const buffer = CoreBuffer.fromObject(
                        (await SodiumWrapper.ready()).crypto_aead_xchacha20poly1305_ietf_decrypt(
                            new Uint8Array(),
                            cipher.cipher.buffer,
                            "",
                            publicnonce,
                            secretKeyBuffer
                        )
                    );
                    return buffer;
                } catch (e) {
                    const error = new CryptoError(CryptoErrorCode.EncryptionDecrypt, `${e}`);
                    throw error;
                }
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }
    }

    public static async decryptWithCounter(
        cipher: CryptoCipher,
        secretKey: CryptoSecretKey | CoreBuffer,
        nonce: CoreBuffer,
        counter: number,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CoreBuffer> {
        if (secretKey instanceof CryptoSecretKey) {
            CryptoValidation.checkNonceForAlgorithm(nonce, secretKey.algorithm);
        } else if (secretKey instanceof CoreBuffer) {
            CryptoValidation.checkEncryptionAlgorithm(algorithm);
            CryptoValidation.checkNonceForAlgorithm(nonce, algorithm);
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongSecretKey,
                "Secret key must either be a CoreBuffer or a CryptoSecretKey object."
            );
        }
        CryptoValidation.checkCounter(counter);

        const publicnonce = this._addCounter(nonce.buffer, counter);

        return await this.decrypt(cipher, secretKey, publicnonce);
    }

    public static createNonce(algorithm: CryptoEncryptionAlgorithm): CoreBuffer {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);

        let nonceLength;
        switch (algorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
            case CryptoEncryptionAlgorithm.AES256_GCM:
                nonceLength = 12;
                break;
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                nonceLength = 24;
                break;
            default:
                throw new CryptoError(
                    CryptoErrorCode.EncryptionWrongAlgorithm,
                    "Encryption algorithm is not supported."
                );
        }
        return CoreBuffer.random(nonceLength);
    }

    /**
     * Creates a new CoreBuffer object and increases it by the counter
     *
     * @param nonce
     * @param counter
     */
    private static _addCounter(nonce: Uint8Array | CoreBuffer, counter: number): CoreBuffer {
        let buffer;
        if (nonce instanceof Uint8Array) {
            buffer = new CoreBuffer(nonce);
        } else if (nonce instanceof CoreBuffer) {
            buffer = nonce;
        } else {
            throw new CryptoError(CryptoErrorCode.EncryptionWrongNonce);
        }

        const clone = buffer.clone().add(counter);

        return clone;
    }
}
