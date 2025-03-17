import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import {
    CryptoExchangePrivateKeyHandle,
    ICryptoExchangePrivateKeyHandle,
    ICryptoExchangePrivateKeyHandleSerialized
} from "./CryptoExchangePrivateKeyHandle";
import {
    CryptoExchangePublicKeyHandle,
    ICryptoExchangePublicKeyHandle,
    ICryptoExchangePublicKeyHandleSerialized
} from "./CryptoExchangePublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoExchangeKeypairHandle}.
 */
export interface ICryptoExchangeKeypairHandleSerialized extends ISerialized {
    pub: ICryptoExchangePublicKeyHandleSerialized;
    prv: ICryptoExchangePrivateKeyHandleSerialized;
}

/**
 * Interface defining the structure of {@link CryptoExchangeKeypairHandle}.
 */
export interface ICryptoExchangeKeypairHandle extends ISerializable {
    publicKey: ICryptoExchangePublicKeyHandle;
    privateKey: ICryptoExchangePrivateKeyHandle;
}

/**
 * Represents a key pair for cryptographic key exchange operations, managed by the crypto layer.
 * This class holds handles to both the public and private keys, allowing for operations
 * that require both parts of the key pair without exposing the raw key material directly in the application.
 * It extends {@link CryptoSerializableAsync} to support asynchronous serialization and deserialization.
 */
@type("CryptoExchangeKeypairHandle")
export class CryptoExchangeKeypairHandle
    extends CryptoSerializableAsync
    implements ICryptoExchangeKeypairHandle, IClearable
{
    /**
     * The public key handle of the key pair.
     */
    @validate()
    @serialize()
    public publicKey: CryptoExchangePublicKeyHandle;

    /**
     * The private key handle of the key pair.
     */
    @validate()
    @serialize()
    public privateKey: CryptoExchangePrivateKeyHandle;

    /**
     * Clears sensitive data associated with this key pair.
     * Since this class only contains handles to keys managed by the crypto provider,
     * no actual clearing of raw key material is performed here.
     */
    public clear(): void {
        // No-op for handle objects as they don't contain the actual key material
        // The actual key material is managed by the crypto provider
    }

    /**
     * Converts the {@link CryptoExchangeKeypairHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoExchangeKeypairHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoExchangeKeypairHandleSerialized {
        return {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false),
            "@type": verbose ? "CryptoExchangeKeypairHandle" : undefined
        };
    }

    /**
     * Asynchronously creates a {@link CryptoExchangeKeypairHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoExchangeKeypairHandle} and
     * interfaces conforming to {@link ICryptoExchangeKeypairHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoExchangeKeypairHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangeKeypairHandle} instance.
     */
    public static async from(
        value: CryptoExchangeKeypairHandle | ICryptoExchangeKeypairHandle
    ): Promise<CryptoExchangeKeypairHandle> {
        return await this.fromAny(value);
    }

    /**
     * Hook method called before the `from` method during deserialization.
     * It performs pre-processing and validation of the input value.
     *
     * @param value - The value being deserialized.
     * @returns The processed value.
     * @throws {@link CryptoError} if the algorithms of the private and public keys do not match.
     */
    protected static override preFrom(value: any): any {
        if (value.pub) {
            value = {
                publicKey: value.pub,
                privateKey: value.prv
            };
        }

        if (value.privateKey.spec !== value.publicKey.spec) {
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                "Spec of private and public key handles do not match."
            );
        }

        return value;
    }

    /**
     * Asynchronously creates a {@link CryptoExchangeKeypairHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoExchangeKeypairHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangeKeypairHandle} instance.
     */
    public static async fromJSON(value: ICryptoExchangeKeypairHandleSerialized): Promise<CryptoExchangeKeypairHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoExchangeKeypairHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoExchangeKeypairHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangeKeypairHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoExchangeKeypairHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
