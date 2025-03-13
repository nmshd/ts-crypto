import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoSignature } from "../../signature/CryptoSignature";
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
    /**
     * An optional ID for the relationship response.
     */
    id?: string;
    /**
     * Serialized handle to the exchange public key of the response.
     */
    exc: ICryptoExchangePublicKeyHandleSerialized;
    /**
     * Serialized handle to the signature public key of the response.
     */
    sig: ICryptoSignaturePublicKeyHandleSerialized;
    /**
     * Serialized handle to the public state of the response.
     */
    sta: ICryptoPublicStateHandleSerialized;
}

/**
 * Interface defining the structure of {@link CryptoRelationshipPublicResponseHandle}.
 */
export interface ICryptoRelationshipPublicResponseHandle extends ISerializable {
    /**
     * An optional ID for the relationship response.
     */
    id?: string;
    /**
     * Handle to the exchange public key of the response.
     */
    exchangeKey: CryptoExchangePublicKeyHandle;
    /**
     * Handle to the signature public key of the response.
     */
    signatureKey: CryptoSignaturePublicKeyHandle;
    /**
     * Handle to the public state of the response.
     */
    state: CryptoPublicStateHandle;
}

/**
 * Represents a handle to a public response within the crypto layer.
 *
 * This class encapsulates references to:
 *  - A signature public key
 *  - An exchange public key
 *  - A public state
 *
 * All are managed by the crypto provider without exposing the raw key material.
 * It extends {@link CryptoSerializableAsync} to support asynchronous serialization
 * and deserialization.
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
     * Converts the {@link CryptoRelationshipPublicResponseHandle} object into a JSON-serializable object.
     *
     * @param verbose If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoRelationshipPublicResponseHandleSerialized} object that is JSON-serializable.
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
     * @param value The value to be converted into a {@link CryptoRelationshipPublicResponseHandle}.
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
     * @param value The value being deserialized.
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
     * @param value JSON object representing the serialized {@link CryptoRelationshipPublicResponseHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicResponseHandle} instance.
     */
    public static async fromJSON(
        value: ICryptoRelationshipPublicResponseHandleSerialized
    ): Promise<CryptoRelationshipPublicResponseHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipPublicResponseHandle} from a Base64-encoded string.
     *
     * @param value Base64-encoded string representing the serialized {@link CryptoRelationshipPublicResponseHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipPublicResponseHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoRelationshipPublicResponseHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Asynchronously verifies a signature using this handle's signatureKey.
     *
     * @param content The data over which the signature was created.
     * @param signature The {@link CryptoSignature} object containing the signature to be verified.
     * @returns A Promise that resolves to a boolean: `true` if verification succeeds, `false` otherwise.
     * @throws {@link CryptoError} with code `SignatureVerify` if verification fails.
     */
    public async verify(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        try {
            const verified = await this.signatureKey.keyPairHandle.verifySignature(
                content.buffer,
                signature.signature.buffer
            );
            return verified;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.SignatureVerify, `${e}`);
        }
    }

    /**
     * Clears all sensitive sub-fields.
     */
    public clear(): void {
        this.exchangeKey.clear();
        this.signatureKey.clear();
        this.state.clear();
    }

    /**
     * Returns a promise resolving to this handle.
     */
    public async toHandle(): Promise<CryptoRelationshipPublicResponseHandle> {
        return await Promise.resolve(this);
    }
}
