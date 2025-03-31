import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { ProviderIdentifier } from "../crypto-layer";
import { CryptoExchangePublicKeyHandle } from "../crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import { CryptoRelationshipPublicResponseHandle } from "../crypto-layer/relationship/CryptoRelationshipPublicResponseHandle";
import { CryptoSignaturePublicKeyHandle } from "../crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import { CryptoPublicStateHandle } from "../crypto-layer/state/CryptoPublicStateHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoExchangePublicKey, ICryptoExchangePublicKeySerialized } from "../exchange/CryptoExchangePublicKey";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignaturePublicKey, ICryptoSignaturePublicKeySerialized } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { CryptoPublicState, ICryptoPublicStateSerialized } from "../state/CryptoPublicState";

/**
 * Represents the serialized form of a relationship public response.
 */
export interface ICryptoRelationshipPublicResponseSerialized extends ISerialized {
    /**
     * An optional ID for the relationship response.
     */
    id?: string;

    /**
     * The serialized exchange public key.
     */
    exc: ICryptoExchangePublicKeySerialized;

    /**
     * The serialized signature public key.
     */
    sig: ICryptoSignaturePublicKeySerialized;

    /**
     * The serialized public state.
     */
    sta: ICryptoPublicStateSerialized;
}

/**
 * Represents the core interface for a relationship public response in libsodium-based form.
 */
export interface ICryptoRelationshipPublicResponse extends ISerializable {
    /**
     * An optional ID for the relationship response.
     */
    id?: string;

    /**
     * The exchange public key.
     */
    exchangeKey: CryptoExchangePublicKey;

    /**
     * The signature public key.
     */
    signatureKey: CryptoSignaturePublicKey;

    /**
     * The public state.
     */
    state: CryptoPublicState;
}

/**
 * The original libsodium-based implementation of a relationship public response.
 */
@type("CryptoRelationshipPublicResponseWithLibsodium")
export class CryptoRelationshipPublicResponseWithLibsodium
    extends CryptoSerializable
    implements ICryptoRelationshipPublicResponse, IClearable
{
    /**
     * An optional ID for the relationship response.
     */
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    /**
     * The signature public key.
     */
    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKey;

    /**
     * The exchange public key.
     */
    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKey;

    /**
     * The public state.
     */
    @validate()
    @serialize()
    public state: CryptoPublicState;

    /**
     * Serializes the response into a JSON-friendly object.
     *
     * @param verbose If true, includes `@type` in the output.
     */
    public override toJSON(verbose = true): ICryptoRelationshipPublicResponseSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            sta: this.state.toJSON(false),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicResponseWithLibsodium" : undefined
        };
    }

    /**
     * Clears all sensitive data.
     */
    public clear(): void {
        this.exchangeKey.clear();
        this.signatureKey.clear();
        this.state.clear();
    }

    /**
     * Verifies a signature over the given content using libsodium logic.
     *
     * @param content The message that was supposedly signed.
     * @param signature The cryptographic signature to verify.
     * @returns True if the signature is valid, false otherwise.
     */
    public async verify(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.signatureKey);
    }

    /**
     * Converts a plain object or another instance into a libsodium-based CryptoRelationshipPublicResponseWithLibsodium.
     */
    public static from(
        value: CryptoRelationshipPublicResponseWithLibsodium | ICryptoRelationshipPublicResponse
    ): CryptoRelationshipPublicResponseWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Hook for preprocessing input during deserialization.
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
     * Converts serialized data to a libsodium-based CryptoRelationshipPublicResponseWithLibsodium.
     */
    public static fromJSON(
        value: ICryptoRelationshipPublicResponseSerialized
    ): CryptoRelationshipPublicResponseWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Converts a Base64-encoded string to a libsodium-based CryptoRelationshipPublicResponseWithLibsodium.
     */
    public static fromBase64(value: string): CryptoRelationshipPublicResponseWithLibsodium {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Checks if all relevant fields are crypto-layer handles.
     * @returns True if crypto-layer, false if libsodium-based.
     */
    public isUsingCryptoLayer(): boolean {
        return (
            this.exchangeKey instanceof CryptoExchangePublicKeyHandle &&
            this.signatureKey instanceof CryptoSignaturePublicKeyHandle &&
            this.state instanceof CryptoPublicStateHandle
        );
    }
}

/**
 * The new combined class that can work with both libsodium-based objects
 * and crypto-layer handles for the keys and state.
 */
@type("CryptoRelationshipPublicResponse")
export class CryptoRelationshipPublicResponse extends CryptoRelationshipPublicResponseWithLibsodium {
    /**
     * Verifies a signature over the given content. Chooses libsodium or crypto-layer logic.
     *
     * @param content The message to verify.
     * @param signature The signature to check.
     */
    public override async verify(
        content: CoreBuffer,
        signature: CryptoSignature,
        provider?: ProviderIdentifier
    ): Promise<boolean> {
        if (provider && this.isUsingCryptoLayer()) {
            try {
                // Use the universal method which might handle both:
                return await CryptoSignatures.verify(content, signature, this.signatureKey);
            } catch (e) {
                throw new CryptoError(CryptoErrorCode.SignatureVerify, `${e}`);
            }
        } else {
            // Fall back to the libsodium-based logic
            return await super.verify(content, signature);
        }
    }

    /**
     * Converts this object into a crypto-layer handle if all fields are handles.
     */
    public async toHandle(): Promise<CryptoRelationshipPublicResponseHandle> {
        if (this.isUsingCryptoLayer()) {
            return await CryptoRelationshipPublicResponseHandle.from({
                id: this.id,
                exchangeKey: await CryptoExchangePublicKeyHandle.fromAny(this.exchangeKey),
                signatureKey: await CryptoSignaturePublicKeyHandle.fromAny(this.signatureKey),
                state: await CryptoPublicStateHandle.fromAny(this.state)
            });
        }
        throw new CryptoError(
            CryptoErrorCode.CalUninitializedKey,
            "Cannot create handle: this response does not use crypto-layer handles"
        );
    }

    /**
     * Creates a new CryptoRelationshipPublicResponse from a crypto-layer handle.
     */
    public static fromHandle(handle: CryptoRelationshipPublicResponseHandle): CryptoRelationshipPublicResponse {
        return CryptoRelationshipPublicResponse.from({
            id: handle.id,
            exchangeKey: handle.exchangeKey,
            signatureKey: handle.signatureKey,
            state: handle.state
        });
    }

    /**
     * Override the base class's `from` method so that we return this child class.
     */
    public static override from(value: any): CryptoRelationshipPublicResponse {
        return super.fromAny(value) as CryptoRelationshipPublicResponse;
    }

    /**
     * Optional override for `preFrom` if you need special handle-based logic.
     */
    protected static override preFrom(value: any): any {
        return super.preFrom(value);
    }

    /**
     * Optional override for `fromJSON`.
     */
    public static override fromJSON(
        value: ICryptoRelationshipPublicResponseSerialized
    ): CryptoRelationshipPublicResponse {
        return super.fromAny(value) as CryptoRelationshipPublicResponse;
    }

    /**
     * Optional override for `fromBase64`.
     */
    public static override fromBase64(value: string): CryptoRelationshipPublicResponse {
        return super.fromBase64(value) as CryptoRelationshipPublicResponse;
    }
}
