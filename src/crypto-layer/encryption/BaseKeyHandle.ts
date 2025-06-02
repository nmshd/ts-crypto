import { ISerializable, ISerialized, SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyHandle, KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { isKeySpec } from "@nmshd/rs-crypto-types/checks";
import { CoreBuffer, ICoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { getProvider, ProviderIdentifier } from "../CryptoLayerProviders";

export interface IBaseKeyHandleSerialized extends ISerialized {
    kid: string;
    pnm: string;
    spc: KeySpec;
}

export interface IBaseKeyHandle extends ISerializable {
    id: string;
    providerName: string;
    spec: KeySpec;
}

export interface BaseKeyHandleConstructor<T extends BaseKeyHandle> {
    new (): T;

    deserialize(value: string): Promise<T>;
    fromProviderAndKeyHandle(
        provider: Provider,
        keyHandle: KeyHandle,
        other?: { providerName?: string; keyId?: string; keySpec?: KeySpec }
    ): Promise<T>;
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

    @validate({
        customValidator: (value) => {
            if (isKeySpec(value)) return undefined;
            return "is not of type keySpec";
        }
    })
    @serialize()
    public spec: KeySpec;

    public provider: Provider;
    public keyHandle: KeyHandle;

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

    /**
     * Creates a new {@link BaseKeyHandle} or its child from an existing {@link KeyHandle}.
     */
    public static async fromProviderAndKeyHandle<T extends BaseKeyHandle>(
        this: new () => T,
        provider: Provider,
        keyHandle: KeyHandle
    ): Promise<T> {
        const result = new this();

        [result.providerName, result.id, result.spec] = await Promise.all([
            provider.providerName(),
            keyHandle.id(),
            keyHandle.spec()
        ]);

        result.provider = provider;
        result.keyHandle = keyHandle;
        return result;
    }

    protected static override preFrom(value: any): any {
        if (value.kid) {
            value = {
                id: value.kid,
                providerName: value.pnm,
                spec: value.spc
            };
        }

        if (!isKeySpec(value.spec)) {
            throw new CryptoError(
                CryptoErrorCode.DeserializeValidation,
                "Validating key spec in preFrom of crypto secret key handle failed."
            );
        }

        return value;
    }

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof this)) {
            throw new CryptoError(CryptoErrorCode.DeserializeValidation, "Expected 'BaseKeyHandle' in postFrom.");
        }

        const provider = getProvider({ providerName: value.providerName });
        const keyHandle = await provider.loadKey(value.id);

        value.keyHandle = keyHandle;
        value.provider = provider;
        return value;
    }
}

export abstract class ImportableBaseKeyHandle extends BaseKeyHandle {
    /**
     * Creates a new {@link BaseKeyHandle} or its child by importing a raw key into a provider.
     */
    public static async fromRawKey<T extends ImportableBaseKeyHandle>(
        this: BaseKeyHandleConstructor<T>,
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
                ImportableBaseKeyHandle.fromRawKey
            );
        }
        return await this.fromProviderAndKeyHandle(provider, keyHandle);
    }
}
