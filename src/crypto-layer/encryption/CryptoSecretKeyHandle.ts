import { ISerializable, ISerialized, SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyHandle, KeySpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer, Encoding } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";

/**
 * Interface defining the serialized form of {@link CryptoSecretKeyHandle}.
 */
export interface ICryptoSecretKeyHandleSerialized extends ISerialized {
    alg: number;
    kid: string;
    pnm: string;
    spc: KeySpec;
}

/**
 * Interface defining the structure of {@link CryptoSecretKeyHandle}.
 */
export interface ICryptoSecretKeyHandle extends ISerializable {
    algorithm: CryptoEncryptionAlgorithm;
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
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public id: string;

    @validate()
    @serialize()
    public providerName: string;

    @validate()
    @serialize()
    public spec: KeySpec;

    public provider: Provider;
    public keyHandle: KeyHandle;

    public override toJSON(verbose = true): ICryptoSecretKeyHandleSerialized {
        return {
            kid: this.id,
            alg: this.algorithm,
            pnm: this.providerName,
            spc: this.spec,
            "@type": verbose ? "CryptoSecretKeyHandle" : undefined
        };
    }

    /**
     * Extracts the raw key material from this handle as a Base64-URL string.
     */
    public async toSerializedString(): Promise<string> {
        const raw = await this.keyHandle.extractKey();
        return CoreBuffer.from(raw).toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    public static async from(
        value: CryptoSecretKeyHandle | ICryptoSecretKeyHandle | CoreBuffer
    ): Promise<CryptoSecretKeyHandle> {
        return await this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.kid) {
            value = {
                algorithm: value.alg,
                id: value.kid,
                providerName: value.pnm,
                spec: value.spc
            };
        }
        return value;
    }

    /**
     * Creates a new CryptoSecretKeyHandle from an existing KeyHandle plus optional data
     * (providerName, keyId, keySpec, etc.).
     */
    public static async newFromProviderAndKeyHandle<T extends CryptoSecretKeyHandle>(
        this: new () => T,
        provider: Provider,
        keyHandle: KeyHandle,
        other?: {
            providerName?: string;
            keyId?: string;
            keySpec?: KeySpec;
            algorithm?: CryptoEncryptionAlgorithm;
        }
    ): Promise<T> {
        const result = new this();

        result.providerName = other?.providerName ?? (await provider.providerName());
        result.id = other?.keyId ?? (await keyHandle.id());
        result.spec = other?.keySpec ?? (await keyHandle.spec());
        result.algorithm = other?.algorithm ?? CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;

        result.provider = provider;
        result.keyHandle = keyHandle;
        return result;
    }

    public static async fromJSON(value: ICryptoSecretKeyHandleSerialized): Promise<CryptoSecretKeyHandle> {
        return await this.fromAny(value);
    }

    public static async fromBase64(value: string): Promise<CryptoSecretKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Imports a raw key (as a CoreBuffer) into the provider as a handle, returning a new CryptoSecretKeyHandle.
     */
    public static async importRawKeyIntoHandle(
        providerIdent: ProviderIdentifier,
        rawKey: CoreBuffer,
        spec: KeySpec,
        algorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoSecretKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const keyHandle = await provider.importKey(spec, rawKey.buffer);
        return await this.newFromProviderAndKeyHandle(provider, keyHandle, { keySpec: spec, algorithm });
    }

    /**
     * Creates a brand-new secret key handle with the given KeySpec and algorithm from the provider.
     */
    public static async generateKeyHandle(
        providerIdent: ProviderIdentifier,
        spec: KeySpec,
        algorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoSecretKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const keyHandle = await provider.createKey(spec);
        return await this.newFromProviderAndKeyHandle(provider, keyHandle, {
            keySpec: spec,
            algorithm
        });
    }

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof CryptoSecretKeyHandle)) {
            throw new CryptoError(CryptoErrorCode.WrongParameters, "Expected 'CryptoSecretKeyHandle' in postFrom.");
        }
        const provider = getProviderOrThrow({ providerName: value.providerName });
        const keyHandle = await provider.loadKey(value.id);

        value.keyHandle = keyHandle;
        (value as CryptoSecretKeyHandle).provider = provider;
        return value;
    }
}
