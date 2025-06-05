import { ISerializable, ISerialized, SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyHandle, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "../../hash/CryptoHash";
import { getProvider } from "../CryptoLayerProviders";
import { CryptoLayerUtils } from "../CryptoLayerUtils";

export interface IBaseKeyHandleSerialized extends ISerialized {
    kid: string;
    pnm: string;
}

export interface IBaseKeyHandle extends ISerializable {
    id: string;
    providerName: string;
}

export interface BaseKeyHandleConstructor<T> {
    new (): T;

    deserialize(value: string): Promise<T>;
    fromAny(value: any): Promise<T>;
}

/**
 * Represents a handle to a secret key used for symmetric encryption/decryption within the crypto layer.
 * This handle encapsulates a reference to the key material, managed by the underlying crypto provider,
 * without exposing the raw key material directly.
 */
@type("BaseKeyHandle")
export abstract class BaseKeyHandle extends CryptoSerializableAsync implements IBaseKeyHandle {
    @validate()
    @serialize()
    public id: string;

    @validate()
    @serialize()
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
     * Deserializes an object representation of a {@link BaseKeyHandle}.
     *
     * This method is not able to import raw keys or {@link KeyHandle}.
     */
    public static async from<T extends BaseKeyHandle>(
        this: BaseKeyHandleConstructor<T>,
        value: BaseKeyHandleConstructor<T> | IBaseKeyHandle | CoreBuffer
    ): Promise<T> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromJSON<T extends BaseKeyHandle>(
        this: BaseKeyHandleConstructor<T>,
        value: IBaseKeyHandleSerialized
    ): Promise<T> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromBase64<T extends BaseKeyHandle>(
        this: BaseKeyHandleConstructor<T>,
        value: string
    ): Promise<T> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    protected static override preFrom(value: any): any {
        if (value.kid) {
            value = {
                id: value.kid,
                providerName: value.pnm,
                spec: value.spc
            };
        }

        return value;
    }

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof this)) {
            throw new CryptoError(CryptoErrorCode.DeserializeValidation, "Expected 'BaseKeyHandle' in postFrom.");
        }

        const provider = getProvider({ providerName: value.providerName });
        let keyHandle: KeyHandle;
        try {
            keyHandle = await provider.loadKey(value.id);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.CalLoadKey,
                "Failed to load key during deserialization.",
                undefined,
                e as Error,
                BaseKeyHandle.postFrom
            );
        }

        value.keyHandle = keyHandle;
        value.provider = provider;
        return value;
    }
}

export abstract class ImportableBaseKeyHandle extends BaseKeyHandle {
    // Phantom marker to make this type incompatible with `BaseKeyHandle`.
    public readonly _importable = true;
}
