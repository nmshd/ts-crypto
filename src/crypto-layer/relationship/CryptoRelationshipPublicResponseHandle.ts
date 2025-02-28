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
import { CryptoPublicStateHandle, ICryptoPublicStateHandleSerialized } from "../state/CryptoPublicStateHandle";

/**
 * Interface defining the serialized form of {@link CryptoRelationshipPublicResponseHandle}.
 */
export interface ICryptoRelationshipPublicResponseHandleSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangePublicKeyHandleSerialized;
    sig: ICryptoSignaturePublicKeyHandleSerialized;
    sta: ICryptoPublicStateHandleSerialized;
}

/**
 * Interface defining the structure of {@link CryptoRelationshipPublicResponseHandle}.
 */
export interface ICryptoRelationshipPublicResponseHandle extends ISerializable {
    id?: string;
    exchangeKey: CryptoExchangePublicKeyHandle;
    signatureKey: CryptoSignaturePublicKeyHandle;
    state: CryptoPublicStateHandle;
}

/**
 * Represents a handle to a public response for a relationship within the crypto layer.
 * This handle encapsulates references to public keys and state, managed by the crypto provider,
 * without exposing the raw key material directly. It extends {@link CryptoSerializableAsync} to support
 * asynchronous serialization and deserialization.
 */
@type("CryptoRelationshipPublicResponseHandle")
export class CryptoRelationshipPublicResponseHandle
    extends CryptoSerializableAsync
    implements ICryptoRelationshipPublicResponseHandle
{
    /**
     * An optional ID for the relationship response.
     */
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    /**
     * Handle to the signature public key of the response.
     */
    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKeyHandle;

    /**
     * Handle to the exchange public key of the response.
     */
    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKeyHandle;

    /**
     * Handle to the public state of the response.
     */
    @validate()
    @serialize()
    public state: CryptoPublicStateHandle;

    /**
     * Converts the {@link CryptoRelationshipPublicResponseHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoRelationshipPublicResponseHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoRelationshipPublicResponseHandleSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            sta: this.state.toJSON(false),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicResponseHandle" : undefined
        };
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipPublicResponseHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoRelationshipPublicResponseHandle} and
     * interfaces conforming to {@link ICryptoRelationshipPublicResponseHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoRelationshipPublicResponseHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicResponseHandle} instance.
     */
    public static async from(
        value: CryptoRelationshipPublicResponseHandle | ICryptoRelationshipPublicResponseHandle
    ): Promise<CryptoRelationshipPublicResponseHandle> {
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
                state: value.sta,
                id: value.id
            };
        }
        return value;
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipPublicResponseHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoRelationshipPublicResponseHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicResponseHandle} instance.
     */
    public static async fromJSON(
        value: ICryptoRelationshipPublicResponseHandleSerialized
    ): Promise<CryptoRelationshipPublicResponseHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipPublicResponseHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoRelationshipPublicResponseHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicResponseHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoRelationshipPublicResponseHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
