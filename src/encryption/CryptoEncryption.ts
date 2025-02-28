import { KeySpec } from "@nmshd/rs-crypto-types";
import { defaults } from "lodash";
import { CoreBuffer } from "../CoreBuffer";
import { getProvider, ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { DEFAULT_KEY_PAIR_SPEC } from "../crypto-layer/CryptoLayerUtils";
import { CryptoEncryptionWithCryptoLayer } from "../crypto-layer/encryption/CryptoEncryptionWithCryptoLayer";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
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
    AES128_GCM = 1,
    AES256_GCM = 2,
    XCHACHA20_POLY1305 = 3
}

export abstract class CryptoEncryptionWithLibsodium {
    // Original Libsodium implementation
    // **CRITICAL CHANGE:  Return type here must be the union**
    public static async generateKey(
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoSecretKey | CryptoSecretKeyHandle> {
        // Corrected return type
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

    public static async encrypt(
        plaintext: CoreBuffer,
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
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
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
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
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
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
        } else if (typeof cipher.nonce !== "undefined") {
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
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
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

let providerInitialized = false;

export function initCryptoEncryption(providerIdent: ProviderIdentifier): void {
    if (getProvider(providerIdent)) {
        providerInitialized = true;
    }
}

export class CryptoEncryption extends CryptoEncryptionWithLibsodium {
    public static override async generateKey(
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
        providerIdent?: ProviderIdentifier,
        spec?: KeySpec
    ): Promise<CryptoSecretKey | CryptoSecretKeyHandle> {
        if (providerInitialized) {
            if (!providerIdent) {
                throw new CryptoError(CryptoErrorCode.CalWrongProvider, "Provider not defined.");
            }
            return await CryptoEncryptionWithCryptoLayer.generateKey(
                providerIdent,
                defaults({ cipher: algorithm }, spec, DEFAULT_KEY_PAIR_SPEC)
            );
        }
        return await super.generateKey(algorithm);
    }

    public static override async encrypt(
        plaintext: CoreBuffer,
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
        nonce?: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoCipher> {
        if (providerInitialized && secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoEncryptionWithCryptoLayer.encrypt(plaintext, secretKey, nonce);
        }
        return await super.encrypt(plaintext, secretKey, nonce, algorithm);
    }

    public static override async encryptWithCounter(
        plaintext: CoreBuffer,
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
        nonce: CoreBuffer,
        counter: number,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoCipher> {
        if (providerInitialized && secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoEncryptionWithCryptoLayer.encryptWithCounter(plaintext, secretKey, nonce, counter);
        }
        return await super.encryptWithCounter(plaintext, secretKey, nonce, counter, algorithm);
    }

    public static override async decrypt(
        cipher: CryptoCipher,
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
        nonce?: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CoreBuffer> {
        if (providerInitialized && secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoEncryptionWithCryptoLayer.decrypt(cipher, secretKey, nonce);
        }
        return await super.decrypt(cipher, secretKey, nonce, algorithm);
    }

    public static override async decryptWithCounter(
        cipher: CryptoCipher,
        secretKey: CryptoSecretKey | CoreBuffer | CryptoSecretKeyHandle,
        nonce: CoreBuffer,
        counter: number,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CoreBuffer> {
        if (providerInitialized && secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoEncryptionWithCryptoLayer.decryptWithCounter(cipher, secretKey, nonce, counter);
        }
        return await super.decryptWithCounter(cipher, secretKey, nonce, counter, algorithm);
    }
}
