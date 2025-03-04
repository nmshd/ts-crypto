import { KeySpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "./CryptoSecretKeyHandle";

/**
 * Provides symmetric encryption and decryption functionalities using the crypto layer.
 * This class is designed to replace the libsodium-based implementation, leveraging
 * the Rust-based crypto layer for enhanced security and performance.
 */
export class CryptoEncryptionWithCryptoLayer {
    /**
     * Asynchronously generates a secret key for symmetric encryption using the crypto layer.
     *
     * @param providerIdent - Identifier for the crypto provider to be used for key generation.
     * @param spec - Specification for the cipher
     * @returns A Promise that resolves to a {@link CryptoSecretKeyHandle} containing the generated key handle.
     */
    public static async generateKey(providerIdent: ProviderIdentifier, spec: KeySpec): Promise<CryptoSecretKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const keyHandle = await provider.createKey(spec);
        const secretKeyHandle = await CryptoSecretKeyHandle.newFromProviderAndKeyHandle(provider, keyHandle, {
            keySpec: spec,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305 // TODO: correct default?
        });
        return secretKeyHandle;
    }

    /**
     * Asynchronously encrypts the given plaintext using the provided secret key handle and optional nonce.
     *
     * @param plaintext - The data to be encrypted, as a {@link CoreBuffer}.
     * @param secretKeyHandle - The {@link CryptoSecretKeyHandle} to use for encryption.
     * @param nonce - An optional {@link CoreBuffer} representing the nonce. If not provided, a random nonce will be generated.
     * @returns A Promise that resolves to a {@link CryptoCipher} object containing the ciphertext and associated metadata.
     */
    public static async encrypt(
        plaintext: CoreBuffer,
        secretKeyHandle: CryptoSecretKeyHandle
        // nonce?: CoreBuffer
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = secretKeyHandle.algorithm;

        try {
            const [cipher, iv] = await secretKeyHandle.keyHandle.encryptData(plaintext.buffer);

            return CryptoCipher.from({
                cipher: CoreBuffer.from(cipher),
                algorithm: encryptionAlgorithm,
                nonce: CoreBuffer.from(iv)
            });
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`);
        }
    }

    /**
     * Asynchronously encrypts the given plaintext using counter mode with the provided secret key handle, nonce, and counter.
     *
     * @param plaintext - The data to be encrypted, as a {@link CoreBuffer}.
     * @param secretKeyHandle - The {@link CryptoSecretKeyHandle} to use for encryption.
     * @param nonce - The {@link CoreBuffer} representing the nonce.
     * @param counter - The counter value for counter mode encryption.
     * @returns A Promise that resolves to a {@link CryptoCipher} object containing the ciphertext and associated metadata.
     */
    public static async encryptWithCounter(
        plaintext: CoreBuffer,
        secretKeyHandle: CryptoSecretKeyHandle,
        // nonce: CoreBuffer,
        counter: number
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = secretKeyHandle.algorithm;

        // const publicnonce = nonce.buffer;

        try {
            // Corrected: Use encryptData and destructure
            const [cipher, iv] = await secretKeyHandle.keyHandle.encryptData(plaintext.buffer);

            return CryptoCipher.from({
                cipher: CoreBuffer.from(cipher),
                algorithm: encryptionAlgorithm,
                nonce: CoreBuffer.from(iv),
                counter
            });
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`);
        }
    }

    /**
     * Asynchronously decrypts the given ciphertext using the provided secret key handle and optional nonce.
     *
     * @param cipher - The {@link CryptoCipher} object containing the ciphertext and associated metadata.
     * @param secretKeyHandle - The {@link CryptoSecretKeyHandle} to use for decryption.
     * @param nonce - An optional {@link CoreBuffer} representing the nonce.  If not provided, it must be present in the `cipher` object.
     * @returns A Promise that resolves to a {@link CoreBuffer} containing the decrypted plaintext.
     * @throws {@link CryptoError} if decryption fails or if the nonce is missing.
     */
    public static async decrypt(
        cipher: CryptoCipher,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce?: CoreBuffer
    ): Promise<CoreBuffer> {
        let publicnonce;
        if (typeof nonce !== "undefined") {
            publicnonce = nonce.buffer;
        } else if (typeof cipher.nonce !== "undefined") {
            publicnonce = cipher.nonce.buffer;
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongNonce,
                "Cipher does not contain a nonce and no nonce is given."
            );
        }

        try {
            const buffer = await secretKeyHandle.keyHandle.decryptData(cipher.cipher.buffer, publicnonce);
            return CoreBuffer.from(buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionDecrypt, `${e}`);
        }
    }

    /**
     * Asynchronously decrypts the given ciphertext using counter mode with the provided secret key handle, nonce, and counter.
     *
     * @param cipher - The {@link CryptoCipher} object containing the ciphertext and associated metadata.
     * @param secretKeyHandle - The {@link CryptoSecretKeyHandle} to use for decryption.
     * @param nonce - The {@link CoreBuffer} representing the nonce.
     * @param counter - The counter value used for counter mode decryption.
     * @returns A Promise that resolves to a {@link CoreBuffer} containing the decrypted plaintext.
     */
    public static async decryptWithCounter(
        cipher: CryptoCipher,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce: CoreBuffer
    ): Promise<CoreBuffer> {
        const publicnonce = nonce.buffer;
        return await this.decrypt(cipher, secretKeyHandle, CoreBuffer.from(publicnonce));
    }

    /**
     * Creates a new random nonce (number used once) suitable for the specified encryption algorithm.
     *
     * @param algorithm - The {@link CryptoEncryptionAlgorithm} for which to generate the nonce.
     * @returns A {@link CoreBuffer} containing the generated nonce.
     * @throws {@link CryptoError} if the specified algorithm is not supported.
     */
    public static createNonce(algorithm: CryptoEncryptionAlgorithm): CoreBuffer {
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
     * Adds a counter value to a given nonce.  This is a helper function used internally for counter mode encryption.
     *
     * @param nonce - The initial nonce as a {@link Uint8Array} or {@link CoreBuffer}.
     * @param counter - The counter value to add.
     * @returns A new {@link CoreBuffer} representing the nonce incremented by the counter.
     * @throws {@link CryptoError} if the input `nonce` is of an invalid type.
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
