/* eslint-disable @typescript-eslint/naming-convention */
import { KeyHandle, KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoValidation } from "../../CryptoValidation";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoSecretKey, ICryptoSecretKey } from "../../encryption/CryptoSecretKey";
import { CryptoHashAlgorithm } from "../../hash/CryptoHash";
import { CryptoLayerProviderIdentifier } from "../CryptoLayerConfig";
import { getProvider } from "../CryptoLayerProviders";
import { CryptoLayerUtils } from "../CryptoLayerUtils";
import { BaseDerivedKeyHandle } from "./BaseDerivedKeyHandle";
import { BaseKeyHandle } from "./BaseKeyHandle";
import { DeviceBoundKeyHandle } from "./DeviceBoundKeyHandle";
import { PortableDerivedKeyHandle } from "./PortableDerivedKeyHandle";
import { PortableKeyHandle } from "./PortableKeyHandle";

export class CryptoEncryptionHandle {
    /**
     * Creates a new {@link BaseKeyHandle} / {@link DerivedBaseKeyHandle} or its child from an existing {@link KeyHandle}.
     */
    public static async _keyHandleFromProviderAndCalKeyHandle<T extends BaseKeyHandle | BaseDerivedKeyHandle>(
        constructor: new () => T,
        provider: Provider,
        keyHandle: KeyHandle
    ): Promise<T> {
        const result = new constructor();

        [result.providerName, result.id] = await Promise.all([provider.providerName(), keyHandle.id()]);

        result.provider = provider;
        result.keyHandle = keyHandle;
        return result;
    }

    private static async generateKeyHandle<T extends BaseKeyHandle>(
        constructor: new () => T,
        providerIdent: CryptoLayerProviderIdentifier,
        spec: KeySpec
    ): Promise<T> {
        const provider = getProvider(providerIdent);
        const keyHandle = await provider.createKey(spec);
        const secretKeyHandle = await CryptoEncryptionHandle._keyHandleFromProviderAndCalKeyHandle(
            constructor,
            provider,
            keyHandle
        );
        return secretKeyHandle;
    }

    public static async generateDeviceBoundKeyHandle(
        providerIdent: CryptoLayerProviderIdentifier,
        encryptionAlgorithm: CryptoEncryptionAlgorithm,
        hashAlgorithm: CryptoHashAlgorithm
    ): Promise<DeviceBoundKeyHandle> {
        const deviceBoundSpec: KeySpec = {
            cipher: CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(encryptionAlgorithm),
            signing_hash: CryptoLayerUtils.cryptoHashFromCryptoHashAlgorithm(hashAlgorithm),
            ephemeral: false,
            non_exportable: true
        };

        return await this.generateKeyHandle<DeviceBoundKeyHandle>(DeviceBoundKeyHandle, providerIdent, deviceBoundSpec);
    }

    public static async generatePortableKeyHandle(
        providerIdent: CryptoLayerProviderIdentifier,
        encryptionAlgorithm: CryptoEncryptionAlgorithm,
        hashAlgorithm: CryptoHashAlgorithm
    ): Promise<PortableKeyHandle> {
        const portableSpec: KeySpec = {
            cipher: CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(encryptionAlgorithm),
            signing_hash: CryptoLayerUtils.cryptoHashFromCryptoHashAlgorithm(hashAlgorithm),
            ephemeral: false,
            non_exportable: false
        };

        return await this.generateKeyHandle<PortableKeyHandle>(PortableKeyHandle, providerIdent, portableSpec);
    }

    public static async encrypt<T extends BaseKeyHandle | BaseDerivedKeyHandle>(
        plaintext: CoreBuffer,
        secretKeyHandle: T,
        nonce?: CoreBuffer
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = await secretKeyHandle.encryptionAlgorithm();

        if (nonce === undefined || nonce.buffer.length === 0) {
            nonce = await this.createNonce({ providerName: secretKeyHandle.providerName }, encryptionAlgorithm);
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

    public static async encryptWithCounter<T extends BaseKeyHandle | BaseDerivedKeyHandle>(
        plaintext: CoreBuffer,
        secretKeyHandle: T,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CryptoCipher> {
        const encryptionAlgorithm = await secretKeyHandle.encryptionAlgorithm();

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

    public static async decrypt<T extends BaseKeyHandle | BaseDerivedKeyHandle>(
        cipher: CryptoCipher,
        secretKeyHandle: T,
        nonce?: CoreBuffer
    ): Promise<CoreBuffer> {
        const encryptionAlgorithm = await secretKeyHandle.encryptionAlgorithm();

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

    public static async decryptWithCounter<T extends BaseKeyHandle | BaseDerivedKeyHandle>(
        cipher: CryptoCipher,
        secretKeyHandle: T,
        nonce: CoreBuffer,
        counter: number
    ): Promise<CoreBuffer> {
        const encryptionAlgorithm = await secretKeyHandle.encryptionAlgorithm();

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

    public static async createNonce(
        providerIdent: CryptoLayerProviderIdentifier,
        algorithm: CryptoEncryptionAlgorithm
    ): Promise<CoreBuffer> {
        const provider = getProvider(providerIdent);

        let nonceLength;
        switch (algorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
            case CryptoEncryptionAlgorithm.AES256_GCM:
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

    public static async extractRawKey(
        portableKeyHandle: PortableKeyHandle | PortableDerivedKeyHandle
    ): Promise<CoreBuffer> {
        const rawKey = await portableKeyHandle.keyHandle.extractKey();
        return new CoreBuffer(rawKey);
    }

    public static async cryptoSecretKeyFromPortableKeyHandle(
        portableKeyHandle: PortableKeyHandle | PortableDerivedKeyHandle
    ): Promise<CryptoSecretKey> {
        const rawKeyPromise = CryptoEncryptionHandle.extractRawKey(portableKeyHandle);
        const algorithm = await portableKeyHandle.encryptionAlgorithm();
        const cryptoSecretKeyObj: ICryptoSecretKey = {
            algorithm: algorithm,
            secretKey: await rawKeyPromise
        };
        return CryptoSecretKey.from(cryptoSecretKeyObj);
    }

    private static async keyHandleFromCryptoSecretKey<T extends BaseKeyHandle | BaseDerivedKeyHandle>(
        constructor: new () => T,
        providerIdent: CryptoLayerProviderIdentifier,
        cryptoSecretKey: CryptoSecretKey,
        signingHash: CryptoHashAlgorithm,
        ephemeral: boolean
    ): Promise<T> {
        const cipher = CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(cryptoSecretKey.algorithm);
        const keySpec: KeySpec = {
            cipher: cipher,
            ephemeral: ephemeral,
            signing_hash: CryptoLayerUtils.cryptoHashFromCryptoHashAlgorithm(signingHash),
            non_exportable: false
        };

        const provider = getProvider(providerIdent);
        let keyHandle: KeyHandle;
        try {
            keyHandle = await provider.importKey(keySpec, cryptoSecretKey.secretKey.buffer);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.CalImportOfKey,
                "Failed to import crypto secret key.",
                undefined,
                e as Error,
                CryptoEncryptionHandle.keyHandleFromCryptoSecretKey
            );
        }

        return await CryptoEncryptionHandle._keyHandleFromProviderAndCalKeyHandle(constructor, provider, keyHandle);
    }

    public static async portableKeyHandleFromCryptoSecretKey(
        providerIdent: CryptoLayerProviderIdentifier,
        cryptoSecretKey: CryptoSecretKey,
        signingHash: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA512
    ): Promise<PortableKeyHandle> {
        return await CryptoEncryptionHandle.keyHandleFromCryptoSecretKey<PortableKeyHandle>(
            PortableKeyHandle,
            providerIdent,
            cryptoSecretKey,
            signingHash,
            false
        );
    }

    public static async portableDerivedKeyHandleFromCryptoSecretKey(
        providerIdent: CryptoLayerProviderIdentifier,
        cryptoSecretKey: CryptoSecretKey,
        signingHash: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA512
    ): Promise<PortableDerivedKeyHandle> {
        return await CryptoEncryptionHandle.keyHandleFromCryptoSecretKey<PortableDerivedKeyHandle>(
            PortableDerivedKeyHandle,
            providerIdent,
            cryptoSecretKey,
            signingHash,
            true
        );
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
