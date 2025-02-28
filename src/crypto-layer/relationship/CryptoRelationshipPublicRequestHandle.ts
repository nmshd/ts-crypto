import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoSecretKeyHandle, ICryptoSecretKeyHandleSerialized } from "../encryption/CryptoSecretKeyHandle";
import {
    CryptoExchangeKeypairHandle,
    ICryptoExchangeKeypairHandleSerialized
} from "../exchange/CryptoExchangeKeypairHandle";
import {
    CryptoExchangePublicKeyHandle,
    ICryptoExchangePublicKeyHandleSerialized
} from "../exchange/CryptoExchangePublicKeyHandle";
import {
    CryptoSignatureKeypairHandle,
    ICryptoSignatureKeypairHandleSerialized
} from "../signature/CryptoSignatureKeypair";
import {
    CryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandleSerialized
} from "../signature/CryptoSignaturePublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoRelationshipRequestSecretsHandle}.
 */
export interface ICryptoRelationshipRequestSecretsHandleSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangeKeypairHandleSerialized;
    sig: ICryptoSignatureKeypairHandleSerialized;
    eph: ICryptoExchangeKeypairHandleSerialized;
    pik: ICryptoSignaturePublicKeyHandleSerialized;
    pxk: ICryptoExchangePublicKeyHandleSerialized;
    key: ICryptoSecretKeyHandleSerialized;
    nnc: string;
}

/**
 * Interface defining the structure of {@link CryptoRelationshipRequestSecretsHandle}.
 */
export interface ICryptoRelationshipRequestSecretsHandle extends ISerializable {
    id?: string;
    exchangeKeypair: CryptoExchangeKeypairHandle;
    signatureKeypair: CryptoSignatureKeypairHandle;
    ephemeralKeypair: CryptoExchangeKeypairHandle;
    peerIdentityKey: CryptoSignaturePublicKeyHandle;
    peerExchangeKey: CryptoExchangePublicKeyHandle;
    secretKey: CryptoSecretKeyHandle;
    nonce: CoreBuffer;
}

/**
 * Represents a handle to the request secrets for a relationship within the crypto layer.
 * This handle encapsulates references to keypairs, public keys, secret key and nonce, managed by the crypto provider,
 * without exposing the raw key material directly. It extends {@link CryptoSerializableAsync} to support
 * asynchronous serialization and deserialization.
 */
@type("CryptoRelationshipRequestSecretsHandle")
export class CryptoRelationshipRequestSecretsHandle
    extends CryptoSerializableAsync
    implements ICryptoRelationshipRequestSecretsHandle
{
    /**
     * An optional ID for the relationship request secrets.
     */
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    /**
     * Handle to the exchange keypair used for the relationship.
     */
    @validate()
    @serialize({ alias: "exc" })
    public exchangeKeypair: CryptoExchangeKeypairHandle;

    /**
     * Handle to the ephemeral exchange keypair used for the relationship request.
     */
    @validate()
    @serialize({ alias: "eph" })
    public ephemeralKeypair: CryptoExchangeKeypairHandle;

    /**
     * Handle to the signature keypair used for the relationship.
     */
    @validate()
    @serialize({ alias: "sig" })
    public signatureKeypair: CryptoSignatureKeypairHandle;

    /**
     * Handle to the peer's identity signature public key.
     */
    @validate()
    @serialize({ alias: "pik" })
    public peerIdentityKey: CryptoSignaturePublicKeyHandle;

    /**
     * Handle to the peer's exchange public key.
     */
    @validate()
    @serialize({ alias: "pxk" })
    public peerExchangeKey: CryptoExchangePublicKeyHandle;

    /**
     * Handle to the secret key used for encrypting the relationship request.
     */
    @validate()
    @serialize({ alias: "key" })
    public secretKey: CryptoSecretKeyHandle;

    /**
     * Nonce (number used once) for the relationship request, ensuring uniqueness and preventing replay attacks.
     */
    @validate()
    @serialize({ alias: "nnc" })
    public nonce: CoreBuffer;

    /**
     * Converts the {@link CryptoRelationshipRequestSecretsHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoRelationshipRequestSecretsHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoRelationshipRequestSecretsHandleSerialized {
        return {
            exc: this.exchangeKeypair.toJSON(false),
            eph: this.ephemeralKeypair.toJSON(false),
            sig: this.signatureKeypair.toJSON(false),
            pik: this.peerIdentityKey.toJSON(false),
            pxk: this.peerExchangeKey.toJSON(false),
            key: this.secretKey.toJSON(false),
            nnc: this.nonce.toBase64URL(),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipRequestSecretsHandle" : undefined
        };
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipRequestSecretsHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoRelationshipRequestSecretsHandle} and
     * interfaces conforming to {@link ICryptoRelationshipRequestSecretsHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoRelationshipRequestSecretsHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipRequestSecretsHandle} instance.
     */
    public static async from(
        value: CryptoRelationshipRequestSecretsHandle | ICryptoRelationshipRequestSecretsHandle
    ): Promise<CryptoRelationshipRequestSecretsHandle> {
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
                exchangeKeypair: value.exc,
                ephemeralKeypair: value.eph,
                signatureKeypair: value.sig,
                peerIdentityKey: value.pik,
                peerExchangeKey: value.pxk,
                secretKey: value.key,
                nonce: value.nnc,
                id: value.id
            };
        }
        return value;
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipRequestSecretsHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoRelationshipRequestSecretsHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipRequestSecretsHandle} instance.
     */
    public static async fromJSON(
        value: ICryptoRelationshipRequestSecretsHandleSerialized
    ): Promise<CryptoRelationshipRequestSecretsHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipRequestSecretsHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoRelationshipRequestSecretsHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipRequestSecretsHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoRelationshipRequestSecretsHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
