import { KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoValidation } from "../../CryptoValidation";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";
import { CryptoLayerUtils } from "../CryptoLayerUtils";
import { CryptoSecretKeyHandle } from "./CryptoSecretKeyHandle";

export class CryptoEncryptionHandle {
    public static async generateKey(providerIdent: ProviderIdentifier, spec: KeySpec): Promise<CryptoSecretKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const keyHandle = await provider.createKey(spec);
        const secretKeyHandle = await CryptoSecretKeyHandle.fromProviderAndKeyHandle(provider, keyHandle, {
            keySpec: spec
        });
        return secretKeyHandle;
    }

    public static async encrypt(
        plaintext: CoreBuffer,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce?: CoreBuffer
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCalCipher(
            secretKeyHandle.spec.cipher
        );

        if (!nonce || nonce.buffer.length === 0) {
            nonce = await this.createNonce(encryptionAlgorithm, secretKeyHandle.provider);
        } else {
            CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);
        }

        let cipher;
        try {
            cipher = await secretKeyHandle.keyHandle.encryptWithIv(plaintext.buffer, nonce.buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`, undefined, e as Error);
        }

        return CryptoCipher.from({
            cipher: CoreBuffer.from(cipher),
            algorithm: encryptionAlgorithm,
            nonce
        });
    }

    public static async encryptWithCounter(
        plaintext: CoreBuffer,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCalCipher(
            secretKeyHandle.spec.cipher
        );

        CryptoValidation.checkCounter(counter);
        CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);

        const publicNonce = this.addCounterToNonce(nonce.buffer, counter);

        let cipher;
        try {
            cipher = await secretKeyHandle.keyHandle.encryptWithIv(plaintext.buffer, publicNonce.buffer);
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

    public static async decrypt(
        cipher: CryptoCipher,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce?: CoreBuffer
    ): Promise<CoreBuffer> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCalCipher(
            secretKeyHandle.spec.cipher
        );

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

    public static async decryptWithCounter(
        cipher: CryptoCipher,
        secretKeyHandle: CryptoSecretKeyHandle,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CoreBuffer> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCalCipher(
            secretKeyHandle.spec.cipher
        );

        CryptoValidation.checkCounter(counter);
        CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);

        const publicNonce = this.addCounterToNonce(nonce.buffer, counter);

        try {
            const buffer = await secretKeyHandle.keyHandle.decryptData(cipher.cipher.buffer, publicNonce.buffer);
            return CoreBuffer.from(buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `${e}`, undefined, e as Error);
        }
    }

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

    private static addCounterToNonce(nonce: Uint8Array | CoreBuffer, counter: number): CoreBuffer {
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
