import { KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoValidation } from "../../CryptoValidation";
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
            keySpec: spec
        });
        return secretKeyHandle;
    }

    /**
     * Asynchronously encrypts the given plaintext using the provided secret key handle and optional nonce.
     *
     * @param plaintext - The data to be encrypted, as a {@link CoreBuffer}.
     * @param secretKeyHandle - The {@link CryptoSecretKeyHandle} to use for encryption.
     * @param nonce - An optional {@link CoreBuffer} representing the nonce. If not provided, a random nonce will be generated.
     * @returns A Promise that resolves to a {@link CryptoCipher} object containing the cipher text and associated metadata.
     */
    public static async encrypt(
        plaintext: CoreBuffer,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce?: CoreBuffer
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = CryptoEncryptionAlgorithm.fromCalCipher(secretKeyHandle.spec.cipher);

        if (!nonce || nonce.buffer.length === 0) {
            nonce = await this.createNonce(encryptionAlgorithm, secretKeyHandle.provider);
        } else {
            CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);
        }

        let cipher;
        let iv;
        try {
            [cipher, iv] = await secretKeyHandle.keyHandle.encryptData(plaintext.buffer, nonce.buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`, undefined, e as Error);
        }

        return CryptoCipher.from({
            cipher: CoreBuffer.from(cipher),
            algorithm: encryptionAlgorithm,
            nonce: new CoreBuffer(iv)
        });
    }

    /**
     * Asynchronously encrypts the given plaintext using counter mode with the provided secret key handle, nonce, and counter.
     *
     * @param plaintext - The data to be encrypted, as a {@link CoreBuffer}.
     * @param secretKeyHandle - The {@link CryptoSecretKeyHandle} to use for encryption.
     * @param nonce - The {@link CoreBuffer} representing the nonce.
     * @param counter - The counter value for counter mode encryption.
     * @returns A Promise that resolves to a {@link CryptoCipher} object containing the cipher text and associated metadata.
     */
    public static async encryptWithCounter(
        plaintext: CoreBuffer,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = CryptoEncryptionAlgorithm.fromCalCipher(secretKeyHandle.spec.cipher);

        CryptoValidation.checkCounter(counter);
        CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);

        const publicNonce = this._addCounter(nonce.buffer, counter);

        let cipher;
        let _iv;
        try {
            [cipher, _iv] = await secretKeyHandle.keyHandle.encryptData(plaintext.buffer, publicNonce.buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`, undefined, e as Error);
        }

        return CryptoCipher.from({
            cipher: CoreBuffer.from(cipher),
            algorithm: encryptionAlgorithm,
            // nonce: new CoreBuffer(iv), // TODO: How is the nonce transmitted?
            counter
        });
    }

    /**
     * Asynchronously decrypts the given cipher text using the provided secret key handle and optional nonce.
     *
     * @param cipher - The {@link CryptoCipher} object containing the cipher text and associated metadata.
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
        const encryptionAlgorithm = CryptoEncryptionAlgorithm.fromCalCipher(secretKeyHandle.spec.cipher);

        let publicNonce;
        if (typeof nonce !== "undefined") {
            CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);
            publicNonce = nonce.buffer;
        } else if (typeof cipher.nonce !== "undefined") {
            publicNonce = cipher.nonce.buffer;
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongNonce,
                "Cipher does not contain a nonce and no nonce is given."
            );
        }

        try {
            const buffer = await secretKeyHandle.keyHandle.decryptData(cipher.cipher.buffer, publicNonce);
            return CoreBuffer.from(buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`, undefined, e as Error);
        }
    }

    /**
     * Asynchronously decrypts the given cipher text using counter mode with the provided secret key handle, nonce, and counter.
     *
     * @param cipher - The {@link CryptoCipher} object containing the cipher text and associated metadata.
     * @param secretKeyHandle - The {@link CryptoSecretKeyHandle} to use for decryption.
     * @param nonce - The {@link CoreBuffer} representing the nonce.
     * @param counter - The counter value used for counter mode decryption.
     * @returns A Promise that resolves to a {@link CoreBuffer} containing the decrypted plaintext.
     */
    public static async decryptWithCounter(
        cipher: CryptoCipher,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CoreBuffer> {
        const encryptionAlgorithm = CryptoEncryptionAlgorithm.fromCalCipher(secretKeyHandle.spec.cipher);

        CryptoValidation.checkCounter(counter);
        CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);

        const publicNonce = this._addCounter(nonce.buffer, counter);

        try {
            const buffer = await secretKeyHandle.keyHandle.decryptData(cipher.cipher.buffer, publicNonce.buffer);
            return CoreBuffer.from(buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`, undefined, e as Error);
        }
    }

    /**
     * Creates a new random nonce (number used once) suitable for the specified encryption algorithm.
     *
     * @param algorithm - The {@link CryptoEncryptionAlgorithm} for which to generate the nonce.
     * @returns A {@link CoreBuffer} containing the generated nonce.
     * @throws {@link CryptoError} if the specified algorithm is not supported.
     */
    public static async createNonce(algorithm: CryptoEncryptionAlgorithm, provider: Provider): Promise<CoreBuffer> {
        let nonceLength;
        switch (algorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
            case CryptoEncryptionAlgorithm.AES256_GCM:
            case CryptoEncryptionAlgorithm.AES128_CBC:
            case CryptoEncryptionAlgorithm.AES256_CBC:
            case CryptoEncryptionAlgorithm.CHACHA20_POLY1305:
                nonceLength = 12;
                break;
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                nonceLength = 24;
                break;
        }

        const buffer = await provider.getRandom(nonceLength);
        return CoreBuffer.from(buffer);
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
