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
    kid: string; // Crypto layer key id used for loading key from a provider.
    pnm: string; // Provider name
    spc: KeySpec; // Specification/Config of key stored.  Now KeySpec
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
 * without exposing the raw key material directly. It extends {@link CryptoSerializableAsync} to support
 * asynchronous serialization and deserialization.
 */
@type("CryptoSecretKeyHandle")
// Corrected: extends CryptoSerializableAsync, not a custom abstract class
export class CryptoSecretKeyHandle extends CryptoSerializableAsync implements ICryptoSecretKeyHandle {
    /**
     * The encryption algorithm for which this secret key is intended.
     */
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    /**
     * The ID of the key within the crypto provider's key management system.
     */
    @validate()
    @serialize()
    public id: string;

    /**
     * The name of the crypto provider managing this key.
     */
    @validate()
    @serialize()
    public providerName: string;

    /**
     * The specification of the key
     */
    @validate()
    @serialize()
    public spec: KeySpec;

    /**
     * The provider instance
     */
    public provider: Provider;

    /**
     * The key handle instance
     */
    public keyHandle: KeyHandle;

    /**
     * Converts the {@link CryptoSecretKeyHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoSecretKeyHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoSecretKeyHandleSerialized {
        return {
            kid: this.id,
            alg: this.algorithm,
            pnm: this.providerName,
            spc: this.spec,
            "@type": verbose ? "CryptoSecretKeyHandle" : undefined
        };
    }

    public async toSerializedString(): Promise<string> {
        const raw = await this.keyHandle.extractKey();
        return CoreBuffer.from(raw).toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    /**
     * Asynchronously creates a {@link CryptoSecretKeyHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoSecretKeyHandle} and
     * interfaces conforming to {@link ICryptoSecretKeyHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoSecretKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoSecretKeyHandle} instance.
     */
    public static async from(value: CryptoSecretKeyHandle | ICryptoSecretKeyHandle): Promise<CryptoSecretKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Hook method called before the `from` method during deserialization.
     * It performs pre-processing and validation of the input value.
     *
     * @param value - The value being deserialized.
     * @returns The processed value.
     */
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
        result.algorithm = other?.algorithm ?? CryptoEncryptionAlgorithm.XCHACHA20_POLY1305; // TODO: correct default?

        result.provider = provider;
        result.keyHandle = keyHandle;
        return result;
    }

    /**
     * Asynchronously creates a {@link CryptoSecretKeyHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoSecretKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoSecretKeyHandle} instance.
     */
    public static async fromJSON(value: ICryptoSecretKeyHandleSerialized): Promise<CryptoSecretKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoSecretKeyHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoSecretKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoSecretKeyHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoSecretKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async fromString(
        providerIdent: ProviderIdentifier,
        value: string,
        spec: KeySpec,
        encoding: Encoding,
        algorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoSecretKeyHandle> {
        const raw = CoreBuffer.fromString(value, encoding).buffer;
        const provider = getProviderOrThrow(providerIdent);
        const keyHandle = await provider.importKey(spec, raw);
        return await CryptoSecretKeyHandle.newFromProviderAndKeyHandle(provider, keyHandle, {
            keySpec: spec,
            algorithm
        });
    }

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof CryptoSecretKeyHandle)) {
            throw new CryptoError(CryptoErrorCode.WrongParameters, "Expected 'CryptoSecretKeyHandle'.");
        }

        const provider = getProviderOrThrow({ providerName: value.providerName });
        const keyHandle = await provider.loadKey(value.id);

        value.keyHandle = keyHandle;
        value.provider = provider;
        return value;
    }
}
