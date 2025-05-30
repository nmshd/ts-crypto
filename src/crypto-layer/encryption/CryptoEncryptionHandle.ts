import { KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoValidation } from "../../CryptoValidation";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { getProvider, ProviderIdentifier } from "../CryptoLayerProviders";
import { CryptoLayerUtils } from "../CryptoLayerUtils";
import { BaseKeyHandle, BaseKeyHandleConstructor } from "./BaseKeyHandle";
import { DeviceBoundKeyHandle } from "./DeviceBoundKeyHandle";
import { PortableKeyHandle } from "./PortableKeyHandle";

export class CryptoEncryptionHandle {
    private static async generateKeyHandle<T extends BaseKeyHandle>(
        constructor: BaseKeyHandleConstructor<T>,
        providerIdent: ProviderIdentifier,
        spec: KeySpec
    ): Promise<T> {
        const provider = getProvider(providerIdent);
        const keyHandle = await provider.createKey(spec);
        const secretKeyHandle = await constructor.fromProviderAndKeyHandle(provider, keyHandle, {
            keySpec: spec
        });
        return secretKeyHandle;
    }

    public static async generateDeviceBoundKeyHandle(
        providerIdent: ProviderIdentifier,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        spec: KeySpec & { non_exportable: true }
    ): Promise<DeviceBoundKeyHandle> {
        return await this.generateKeyHandle<DeviceBoundKeyHandle>(DeviceBoundKeyHandle, providerIdent, spec);
    }

    public static async generatePortableKeyHandle(
        providerIdent: ProviderIdentifier,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        spec: KeySpec & { non_exportable: false }
    ): Promise<PortableKeyHandle> {
        return await this.generateKeyHandle<PortableKeyHandle>(PortableKeyHandle, providerIdent, spec);
    }

    public static async encrypt<T extends BaseKeyHandle>(
        plaintext: CoreBuffer,
        secretKeyHandle: T,
        nonce?: CoreBuffer
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(secretKeyHandle.spec.cipher);

        if (nonce === undefined || nonce.buffer.length === 0) {
            nonce = await this.createNonce(encryptionAlgorithm, secretKeyHandle.provider);
        } else {
            CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);
        }

        let cipher;
        try {
            cipher = await secretKeyHandle.keyHandle.encryptWithIv(plaintext.buffer, nonce.buffer);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.EncryptionEncrypt,
                `${e}`,
                undefined,
                e as Error,
                CryptoEncryptionHandle.encrypt
            );
        }

        return CryptoCipher.from({
            cipher: CoreBuffer.from(cipher),
            algorithm: encryptionAlgorithm,
            nonce
        });
    }

    public static async encryptWithCounter<T extends BaseKeyHandle>(
        plaintext: CoreBuffer,
        secretKeyHandle: T,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(secretKeyHandle.spec.cipher);

        CryptoValidation.checkCounter(counter);
        CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);

        const publicNonce = this._addCounter(nonce.buffer, counter);

        let cipher;
        try {
            cipher = await secretKeyHandle.keyHandle.encryptWithIv(plaintext.buffer, publicNonce.buffer);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.EncryptionEncrypt,
                `${e}`,
                undefined,
                e as Error,
                CryptoEncryptionHandle.encryptWithCounter
            );
        }

        return CryptoCipher.from({
            cipher: CoreBuffer.from(cipher),
            algorithm: encryptionAlgorithm,
            counter
        });
    }

    public static async decrypt<T extends BaseKeyHandle>(
        cipher: CryptoCipher,
        secretKeyHandle: T,
        nonce?: CoreBuffer
    ): Promise<CoreBuffer> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(secretKeyHandle.spec.cipher);

        let publicNonce;
        if (nonce !== undefined) {
            CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);
            publicNonce = nonce.buffer;
        } else if (cipher.nonce !== undefined) {
            publicNonce = cipher.nonce.buffer;
        } else {
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongNonce,
                "Cipher does not contain a nonce and no nonce is given."
            ).setContext(CryptoEncryptionHandle.decrypt);
        }

        try {
            const buffer = await secretKeyHandle.keyHandle.decryptData(cipher.cipher.buffer, publicNonce);
            return CoreBuffer.from(buffer);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.EncryptionEncrypt,
                `${e}`,
                undefined,
                e as Error,
                CryptoEncryptionHandle.decrypt
            );
        }
    }

    public static async decryptWithCounter<T extends BaseKeyHandle>(
        cipher: CryptoCipher,
        secretKeyHandle: T,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CoreBuffer> {
        const encryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(secretKeyHandle.spec.cipher);

        CryptoValidation.checkCounter(counter);
        CryptoValidation.checkNonceForAlgorithm(nonce, encryptionAlgorithm);

        const publicNonce = this._addCounter(nonce.buffer, counter);

        try {
            const buffer = await secretKeyHandle.keyHandle.decryptData(cipher.cipher.buffer, publicNonce.buffer);
            return CoreBuffer.from(buffer);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.EncryptionDecrypt,
                `${e}`,
                undefined,
                e as Error,
                CryptoEncryptionHandle.decryptWithCounter
            );
        }
    }

    public static async createNonce(algorithm: CryptoEncryptionAlgorithm, provider: Provider): Promise<CoreBuffer> {
        let nonceLength;
        switch (algorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
            case CryptoEncryptionAlgorithm.AES256_GCM:
            case CryptoEncryptionAlgorithm.CHACHA20_POLY1305:
                nonceLength = 12;
                break;
            case CryptoEncryptionAlgorithm.AES128_CBC:
            case CryptoEncryptionAlgorithm.AES256_CBC:
                nonceLength = 16;
                break;
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                nonceLength = 24;
                break;
        }

        const buffer = await provider.getRandom(nonceLength);
        return CoreBuffer.from(buffer);
    }

    private static _addCounter(nonce: Uint8Array | CoreBuffer, counter: number): CoreBuffer {
        let buffer;
        if (nonce instanceof Uint8Array) {
            buffer = new CoreBuffer(nonce);
        } else if (nonce instanceof CoreBuffer) {
            buffer = nonce;
        } else {
            throw new CryptoError(CryptoErrorCode.EncryptionWrongNonce).setContext(
                CryptoEncryptionHandle.decryptWithCounter
            );
        }

        const clone = buffer.clone().add(counter);

        return clone;
    }
}
