import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSerializable } from "../CryptoSerializable";
import {
    CryptoExchangePublicKey,
    ICryptoExchangePublicKey,
    ICryptoExchangePublicKeySerialized
} from "../exchange/CryptoExchangePublicKey";
import {
    CryptoSignaturePublicKey,
    ICryptoSignaturePublicKey,
    ICryptoSignaturePublicKeySerialized
} from "../signature/CryptoSignaturePublicKey";

/**
 * Interface defining the serialized form of {@link CryptoRelationshipPublicRequestWithLibsodium}.
 */
export interface ICryptoRelationshipPublicRequestSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangePublicKeySerialized;
    sig: ICryptoSignaturePublicKeySerialized;
    eph: ICryptoExchangePublicKeySerialized;
    nnc: string;
}

/**
 * Interface defining the structure of {@link CryptoRelationshipPublicRequestWithLibsodium}.
 */
export interface ICryptoRelationshipPublicRequest extends ISerializable {
    id?: string;
    exchangeKey: ICryptoExchangePublicKey;
    signatureKey: ICryptoSignaturePublicKey;
    ephemeralKey: ICryptoExchangePublicKey;
    nonce: ICoreBuffer;
}

/**
 * The original libsodium-based implementation preserved for backward compatibility.
 */
@type("CryptoRelationshipPublicRequestWithLibsodium")
export class CryptoRelationshipPublicRequestWithLibsodium
    extends CryptoSerializable
    implements ICryptoRelationshipPublicRequest, IClearable
{
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKey;

    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKey;

    @validate()
    @serialize()
    public ephemeralKey: CryptoExchangePublicKey;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    /**
     * Serializes the public request into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoRelationshipPublicRequestSerialized}.
     */
    public override toJSON(verbose = true): ICryptoRelationshipPublicRequestSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            eph: this.ephemeralKey.toJSON(false),
            nnc: this.nonce.toBase64URL(),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicRequestWithLibsodium" : undefined
        };
    }

    /**
     * Clears all sensitive data contained in this public request.
     */
    public clear(): void {
        this.exchangeKey.clear();
        this.signatureKey.clear();
        this.ephemeralKey.clear();
        this.nonce.clear();
    }

    /**
     * Creates an instance of {@link CryptoRelationshipPublicRequestWithLibsodium} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoRelationshipPublicRequest} or an instance.
     * @returns An instance of {@link CryptoRelationshipPublicRequestWithLibsodium}.
     */
    public static from(
        value: CryptoRelationshipPublicRequestWithLibsodium | ICryptoRelationshipPublicRequest
    ): CryptoRelationshipPublicRequestWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Pre-processes the input object to normalize key aliases.
     *
     * @param value - The raw input object.
     * @returns The normalized object.
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
     * Deserializes a JSON object into a {@link CryptoRelationshipPublicRequestWithLibsodium} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoRelationshipPublicRequestSerialized}.
     * @returns An instance of {@link CryptoRelationshipPublicRequestWithLibsodium}.
     */
    public static fromJSON(
        value: ICryptoRelationshipPublicRequestSerialized
    ): CryptoRelationshipPublicRequestWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoRelationshipPublicRequestWithLibsodium} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoRelationshipPublicRequestWithLibsodium}.
     */
    public static fromBase64(value: string): CryptoRelationshipPublicRequestWithLibsodium {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}

/**
 * Extended class that supports handle-based keys if the crypto-layer provider is available.
 * Otherwise, it falls back to the libsodium-based implementation.
 */
@type("CryptoRelationshipPublicRequest")
export class CryptoRelationshipPublicRequest extends CryptoRelationshipPublicRequestWithLibsodium {
    /**
     * Overrides `toJSON` to produce `@type: "CryptoRelationshipPublicRequest"`.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation with the extended type.
     */
    public override toJSON(verbose = true): ICryptoRelationshipPublicRequestSerialized {
        const raw = super.toJSON(false);
        raw["@type"] = verbose ? "CryptoRelationshipPublicRequest" : undefined;
        return raw;
    }

    /**
     * Ensures that an instance of {@link CryptoRelationshipPublicRequest} is returned.
     *
     * @param value - An instance of {@link CryptoRelationshipPublicRequestWithLibsodium} or an object conforming to {@link ICryptoRelationshipPublicRequest}.
     * @returns An instance of {@link CryptoRelationshipPublicRequest}.
     */
    public static override from(
        value: CryptoRelationshipPublicRequestWithLibsodium | ICryptoRelationshipPublicRequest
    ): CryptoRelationshipPublicRequest {
        const base = super.fromAny(value); // Returns a CryptoRelationshipPublicRequestWithLibsodium instance.
        // Convert to the extended class.
        const extended = new CryptoRelationshipPublicRequest();
        extended.id = base.id;
        extended.signatureKey = base.signatureKey;
        extended.exchangeKey = base.exchangeKey;
        extended.ephemeralKey = base.ephemeralKey;
        extended.nonce = base.nonce;
        return extended;
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoRelationshipPublicRequest} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoRelationshipPublicRequest}.
     */
    public static override fromBase64(value: string): CryptoRelationshipPublicRequest {
        return this.fromBase64ToExtended(value);
    }

    /**
     * Helper method that converts a Base64 encoded string to an extended instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoRelationshipPublicRequest}.
     */
    private static fromBase64ToExtended(value: string): CryptoRelationshipPublicRequest {
        const raw = super.fromBase64(value); // Returns a CryptoRelationshipPublicRequestWithLibsodium instance.
        return this.from(raw);
    }
}
