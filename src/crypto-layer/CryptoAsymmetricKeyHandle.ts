import { SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializableAsync } from "../CryptoSerializable";
import { getProvider } from "./CryptoLayerProviders";

/**
 * Type guard to check if a value can be initialized as a CryptoAsymmetricKeyHandle.
 *
 * @param value - The value to check
 * @returns True if the value has the required properties of a CryptoAsymmetricKeyHandle
 */
function isCryptoAsymmetricKeyHandle(value: any): value is CryptoAsymmetricKeyHandle {
    return typeof value["providerName"] === "string" && typeof value["id"] === "string";
}

/**
 * Base class for asymmetric cryptographic key handles.
 *
 * This class provides functionality for managing asymmetric cryptographic keys through
 * the crypto layer. It handles serialization, deserialization, and interaction with
 * the underlying cryptographic provider.
 */
@type("CryptoAsymmetricKeyHandle")
export class CryptoAsymmetricKeyHandle extends CryptoSerializableAsync {
    /**
     * The specification of the key pair, including algorithm and security parameters.
     */
    @validate()
    @serialize()
    public spec: KeyPairSpec;

    /**
     * The unique identifier of the key pair.
     */
    @validate()
    @serialize()
    public id: string;

    /**
     * The name of the cryptographic provider managing this key.
     */
    @validate()
    @serialize()
    public providerName: string;

    /**
     * The cryptographic provider instance.
     */
    public provider: Provider;

    /**
     * The handle to the underlying key pair in the crypto layer.
     */
    public keyPairHandle: KeyPairHandle;

    /**
     * Creates a new instance of CryptoAsymmetricKeyHandle from a provider and key pair handle.
     *
     * @param provider - The cryptographic provider
     * @param keyPairHandle - The handle to the key pair in the crypto layer
     * @param other - Optional parameters to override default values
     * @returns A Promise that resolves to a new instance of the class
     */
    public static async newFromProviderAndKeyPairHandle<T extends CryptoAsymmetricKeyHandle>(
        this: new () => T,
        provider: Provider,
        keyPairHandle: KeyPairHandle,
        other?: {
            providerName?: string;
            keyId?: string;
            keySpec?: KeyPairSpec;
        }
    ): Promise<T> {
        const result = new this();

        result.providerName = other?.providerName ?? (await provider.providerName());
        result.id = other?.keyId ?? (await keyPairHandle.id());
        result.spec = other?.keySpec ?? (await keyPairHandle.spec());

        result.provider = provider;
        result.keyPairHandle = keyPairHandle;
        return result;
    }

    /**
     * Creates a new instance from any compatible value.
     *
     * @param value - The value to convert to a CryptoAsymmetricKeyHandle
     * @returns A Promise that resolves to a new CryptoAsymmetricKeyHandle
     */
    public static async from(value: any): Promise<CryptoAsymmetricKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Creates a new instance from a base64-encoded string.
     *
     * @param value - The base64-encoded string to deserialize
     * @returns A Promise that resolves to a new CryptoAsymmetricKeyHandle
     */
    public static async fromBase64(value: string): Promise<CryptoAsymmetricKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Post-processing after deserialization to initialize provider and key handle.
     *
     * @param value - The deserialized value
     * @returns A Promise that resolves to the initialized instance
     * @throws {@link CryptoError} with {@link CryptoErrorCode.WrongParameters} if the value is not a valid CryptoAsymmetricKeyHandle
     * @throws {@link CryptoError} with {@link CryptoErrorCode.CalFailedLoadingProvider} if the provider cannot be loaded
     */
    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!isCryptoAsymmetricKeyHandle(value)) {
            throw new CryptoError(CryptoErrorCode.WrongParameters, `Expected 'CryptoAsymmetricKeyHandle'.`);
        }
        const provider = getProvider({ providerName: value.providerName });
        if (!provider) {
            throw new CryptoError(
                CryptoErrorCode.CalFailedLoadingProvider,
                `Failed loading provider ${value.providerName}`
            );
        }
        const keyHandle = await provider.loadKeyPair(value.id);

        value.keyPairHandle = keyHandle;
        value.provider = provider;
        return value;
    }
}
