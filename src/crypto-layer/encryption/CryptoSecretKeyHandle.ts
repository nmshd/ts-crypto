import { ISerializable, ISerialized, SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyHandle, KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { isKeySpec } from "@nmshd/rs-crypto-types/checks";
import { CoreBuffer, ICoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { getProvider, ProviderIdentifier } from "../CryptoLayerProviders";

export interface ICryptoSecretKeyHandleSerialized extends ISerialized {
    kid: string;
    pnm: string;
    spc: KeySpec;
}

export interface ICryptoSecretKeyHandle extends ISerializable {
    id: string;
    providerName: string;
    spec: KeySpec;
}

/**
 * Represents a handle to a secret key used for symmetric encryption/decryption within the crypto layer.
 * This handle encapsulates a reference to the key material, managed by the underlying crypto provider,
 * without exposing the raw key material directly.
 */
@type("CryptoSecretKeyHandle")
export class CryptoSecretKeyHandle extends CryptoSerializableAsync implements ICryptoSecretKeyHandle {
    @validate()
    @serialize()
    public id: string;

    @validate()
    @serialize()
    public providerName: string;

    @serialize()
    public spec: KeySpec;

    public provider: Provider;
    public keyHandle: KeyHandle;

    public override toJSON(verbose = true): ICryptoSecretKeyHandleSerialized {
        return {
            kid: this.id,
            pnm: this.providerName,
            spc: this.spec,
            "@type": verbose ? "CryptoSecretKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Deserializes an object representation of a {@link CryptoSecretKeyHandle}.
     *
     * This method is not able to import raw keys or {@link KeyHandle}.
     */
    public static async from(
        value: CryptoSecretKeyHandle | ICryptoSecretKeyHandle | CoreBuffer
    ): Promise<CryptoSecretKeyHandle> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromJSON(value: ICryptoSecretKeyHandleSerialized): Promise<CryptoSecretKeyHandle> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromBase64(value: string): Promise<CryptoSecretKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Creates a new {@link CryptoSecretKeyHandle} from an existing {@link KeyHandle}.
     *
     * `other` is an optional object, where metadata, that is by default derived from asynchronous calls
     * to the {@link Provider} and {@link KeyHandle}, may be provided manually.
     */
    public static async fromProviderAndKeyHandle<T extends CryptoSecretKeyHandle>(
        this: new () => T,
        provider: Provider,
        keyHandle: KeyHandle,
        other?: {
            providerName?: string;
            keyId?: string;
            keySpec?: KeySpec;
        }
    ): Promise<T> {
        const result = new this();

        [result.providerName, result.id, result.spec] = await Promise.all([
            other?.providerName ?? provider.providerName(),
            other?.keyId ?? keyHandle.id(),
            other?.keySpec ?? keyHandle.spec()
        ]);

        result.provider = provider;
        result.keyHandle = keyHandle;
        return result;
    }

    /**
     * Creates a new {@link CryptoSecretKeyHandle} by importing a raw key into a provider.
     */
    public static async fromRawKey(
        providerIdent: ProviderIdentifier,
        rawKey: ICoreBuffer,
        spec: KeySpec
    ): Promise<CryptoSecretKeyHandle> {
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
                CryptoSecretKeyHandle.fromRawKey
            );
        }
        return await this.fromProviderAndKeyHandle(provider, keyHandle, { keySpec: spec });
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
        if (!(value instanceof CryptoSecretKeyHandle)) {
            throw new CryptoError(
                CryptoErrorCode.DeserializeValidation,
                "Expected 'CryptoSecretKeyHandle' in postFrom."
            );
        }

        const provider = getProvider({ providerName: value.providerName });
        const keyHandle = await provider.loadKey(value.id);

        value.keyHandle = keyHandle;
        value.provider = provider;
        return value;
    }
}
