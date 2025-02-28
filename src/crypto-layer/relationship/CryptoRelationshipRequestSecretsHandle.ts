import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import {
    CryptoExchangePublicKeyHandle,
    ICryptoExchangePublicKeyHandleSerialized
} from "../exchange/CryptoExchangePublicKeyHandle";
import {
    CryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandleSerialized
} from "../signature/CryptoSignaturePublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoRelationshipPublicRequestHandle}.
 */
export interface ICryptoRelationshipPublicRequestHandleSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangePublicKeyHandleSerialized;
    sig: ICryptoSignaturePublicKeyHandleSerialized;
    eph: ICryptoExchangePublicKeyHandleSerialized;
    nnc: string;
}

/**
 * Interface defining the structure of {@link CryptoRelationshipPublicRequestHandle}.
 */
export interface ICryptoRelationshipPublicRequestHandle extends ISerializable {
    id?: string;
    exchangeKey: CryptoExchangePublicKeyHandle;
    signatureKey: CryptoSignaturePublicKeyHandle;
    ephemeralKey: CryptoExchangePublicKeyHandle;
    nonce: CoreBuffer;
}

/**
 * Represents a handle to a public request for a relationship within the crypto layer.
 * This handle encapsulates references to public keys and nonce, managed by the crypto provider,
 * without exposing the raw key material directly. It extends {@link CryptoSerializableAsync} to support
 * asynchronous serialization and deserialization.
 */
@type("CryptoRelationshipPublicRequestHandle")
export class CryptoRelationshipPublicRequestHandle
    extends CryptoSerializableAsync
    implements ICryptoRelationshipPublicRequestHandle
{
    /**
     * An optional ID for the relationship request.
     */
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    /**
     * Handle to the exchange public key of the request.
     */
    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKeyHandle;

    /**
     * Handle to the signature public key of the request.
     */
    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKeyHandle;

    /**
     * Handle to the ephemeral exchange public key used for key agreement in the request.
     */
    @validate()
    @serialize()
    public ephemeralKey: CryptoExchangePublicKeyHandle;

    /**
     * Nonce (number used once) for the request, ensuring uniqueness and preventing replay attacks.
     */
    @validate()
    @serialize()
    public nonce: CoreBuffer;

    /**
     * Converts the {@link CryptoRelationshipPublicRequestHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoRelationshipPublicRequestHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoRelationshipPublicRequestHandleSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            eph: this.ephemeralKey.toJSON(false),
            nnc: this.nonce.toBase64URL(),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicRequestHandle" : undefined
        };
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipPublicRequestHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoRelationshipPublicRequestHandle} and
     * interfaces conforming to {@link ICryptoRelationshipPublicRequestHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoRelationshipPublicRequestHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicRequestHandle} instance.
     */
    public static async from(
        value: CryptoRelationshipPublicRequestHandle | ICryptoRelationshipPublicRequestHandle
    ): Promise<CryptoRelationshipPublicRequestHandle> {
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
        if (value.exc) {
            value = {
                exchangeKey: value.exc,
                signatureKey: value.sig,
                ephemeralKey: value.eph,
                nonce: value.nnc,
                id: value.id
            };
        }
        return value;
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipPublicRequestHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoRelationshipPublicRequestHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicRequestHandle} instance.
     */
    public static async fromJSON(
        value: ICryptoRelationshipPublicRequestHandleSerialized
    ): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipPublicRequestHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoRelationshipPublicRequestHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicRequestHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
