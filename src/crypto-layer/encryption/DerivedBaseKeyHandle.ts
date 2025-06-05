// filepath: m:\DEV\WorkProjects\nmshd2\ts-crypto\src\crypto-layer\encryption\DerivedBaseKeyHandle.ts
import { KeyHandle, KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { ICoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption"; // Path relative to src/crypto-layer/encryption/
import { CryptoHashAlgorithm } from "../../hash/CryptoHash"; // Assuming 'src/' is a root path or alias
import { getProvider, ProviderIdentifier } from "../CryptoLayerProviders";
import { CryptoLayerUtils } from "../CryptoLayerUtils"; // Path relative to src/crypto-layer/encryption/

export interface DerivedBaseKeyHandleConstructor<T> {
    new (): T;

    fromProviderAndKeyHandle(provider: Provider, keyHandle: KeyHandle): Promise<T>;
}

/**
 * Variant of {@link BaseKeyHandle} without serialization and deserialization.
 */
export abstract class DerivedBaseKeyHandle {
    public id: string;
    public providerName: string;

    public provider: Provider;
    public keyHandle: KeyHandle;

    public async encryptionAndHashAlgorithm(): Promise<[CryptoEncryptionAlgorithm, CryptoHashAlgorithm]> {
        const spec = await this.keyHandle.spec();
        return [
            CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(spec.cipher),
            CryptoLayerUtils.cryptoHashAlgorithmFromCryptoHash(spec.signing_hash)
        ];
    }

    public async encryptionAlgorithm(): Promise<CryptoEncryptionAlgorithm> {
        const spec = await this.keyHandle.spec();
        return CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(spec.cipher);
    }

    public async hashAlgorithm(): Promise<CryptoHashAlgorithm> {
        const spec = await this.keyHandle.spec();
        return CryptoLayerUtils.cryptoHashAlgorithmFromCryptoHash(spec.signing_hash);
    }

    /**
     * Creates a new {@link DerivedBaseKeyHandle} or its child from an existing {@link KeyHandle}.
     */
    public static async fromProviderAndKeyHandle<T extends DerivedBaseKeyHandle>(
        this: new () => T,
        provider: Provider,
        keyHandle: KeyHandle
    ): Promise<T> {
        const result = new this();

        [result.providerName, result.id] = await Promise.all([provider.providerName(), keyHandle.id()]);

        result.provider = provider;
        result.keyHandle = keyHandle;
        return result;
    }
}

export abstract class ImportableDerivedBaseKeyHandle extends DerivedBaseKeyHandle {
    /**
     * Creates a new {@link BaseKeyHandle} or its child by importing a raw key into a provider.
     */
    public static async fromRawKey<T extends ImportableDerivedBaseKeyHandle>(
        this: DerivedBaseKeyHandleConstructor<T>,
        providerIdent: ProviderIdentifier,
        rawKey: ICoreBuffer,
        spec: KeySpec
    ): Promise<T> {
        const provider = getProvider(providerIdent);
        let keyHandle;
        try {
            keyHandle = await provider.importKey(spec, rawKey.buffer);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.CalImportOfKey,
                "Failed to import raw symmetric key.",
                undefined,
                e as Error,
                ImportableDerivedBaseKeyHandle.fromRawKey
            );
        }
        return await this.fromProviderAndKeyHandle(provider, keyHandle);
    }
}
