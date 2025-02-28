import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoRelationshipType } from "../../relationship/CryptoRelationshipType";
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
import { CryptoPrivateStateHandle, ICryptoPrivateStateHandleSerialized } from "../state/CryptoPrivateStateHandle";

/**
 * Interface defining the serialized form of {@link CryptoRelationshipSecretsHandle}.
 */
export interface ICryptoRelationshipSecretsHandleSerialized extends ISerialized {
    id?: string;
    typ: CryptoRelationshipType;
    exc: ICryptoExchangeKeypairHandleSerialized;
    sig: ICryptoSignatureKeypairHandleSerialized;
    tx: ICryptoPrivateStateHandleSerialized;
    rx: ICryptoPrivateStateHandleSerialized;
    pxk: ICryptoExchangePublicKeyHandleSerialized;
    psk: ICryptoSignaturePublicKeyHandleSerialized;
    ptk: ICryptoExchangePublicKeyHandleSerialized;
    pik?: ICryptoSignaturePublicKeyHandleSerialized;
    rsk: ICryptoSecretKeyHandleSerialized;
}

/**
 * Interface defining the structure of {@link CryptoRelationshipSecretsHandle}.
 */
export interface ICryptoRelationshipSecretsHandle extends ISerializable {
    id?: string;
    type: CryptoRelationshipType;
    exchangeKeypair: CryptoExchangeKeypairHandle;
    signatureKeypair: CryptoSignatureKeypairHandle;
    transmitState: CryptoPrivateStateHandle;
    receiveState: CryptoPrivateStateHandle;
    peerExchangeKey: CryptoExchangePublicKeyHandle;
    peerSignatureKey: CryptoSignaturePublicKeyHandle;
    peerTemplateKey: CryptoExchangePublicKeyHandle;
    peerIdentityKey?: CryptoSignaturePublicKeyHandle;
    requestSecretKey: CryptoSecretKeyHandle;
}

/**
 * Represents a handle to the secrets of a relationship within the crypto layer.
 * This handle encapsulates references to keypairs, states and secret keys, managed by the crypto provider,
 * without exposing the raw key material directly. It extends {@link CryptoSerializableAsync} to support
 * asynchronous serialization and deserialization.
 */
@type("CryptoRelationshipSecretsHandle")
export class CryptoRelationshipSecretsHandle
    extends CryptoSerializableAsync
    implements ICryptoRelationshipSecretsHandle
{
    /**
     * An optional ID for the relationship secrets.
     */
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    /**
     * The type of the relationship (e.g., Requestor, Templator).
     */
    @validate()
    @serialize({ alias: "typ" })
    public type: CryptoRelationshipType;

    /**
     * Handle to the exchange keypair used in the relationship.
     */
    @validate()
    @serialize({ alias: "exc" })
    public exchangeKeypair: CryptoExchangeKeypairHandle;

    /**
     * Handle to the signature keypair used in the relationship.
     */
    @validate()
    @serialize({ alias: "sig" })
    public signatureKeypair: CryptoSignatureKeypairHandle;

    /**
     * Handle to the transmit private state for secure communication.
     */
    @validate()
    @serialize({ alias: "tx" })
    public transmitState: CryptoPrivateStateHandle;

    /**
     * Handle to the receive private state for secure communication.
     */
    @validate()
    @serialize({ alias: "rx" })
    public receiveState: CryptoPrivateStateHandle;

    /**
     * Handle to the peer's exchange public key.
     */
    @validate()
    @serialize({ alias: "pxk" })
    public peerExchangeKey: CryptoExchangePublicKeyHandle;

    /**
     * Handle to the peer's signature public key.
     */
    @validate()
    @serialize({ alias: "psk" })
    public peerSignatureKey: CryptoSignaturePublicKeyHandle;

    /**
     * Handle to the peer's template exchange public key.
     */
    @validate()
    @serialize({ alias: "ptk" })
    public peerTemplateKey: CryptoExchangePublicKeyHandle;

    /**
     * Optional handle to the peer's identity signature public key.
     */
    @validate({ nullable: true })
    @serialize({ alias: "pik" })
    public peerIdentityKey?: CryptoSignaturePublicKeyHandle;

    /**
     * Handle to the secret key used for the relationship request.
     */
    @validate()
    @serialize({ alias: "rsk" })
    public requestSecretKey: CryptoSecretKeyHandle;

    /**
     * Converts the {@link CryptoRelationshipSecretsHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoRelationshipSecretsHandleSerialized} object that is JSON serializable.
     */
    public override async toJSON(verbose = true): Promise<ICryptoRelationshipSecretsHandleSerialized> {
        // Now async
        return {
            exc: this.exchangeKeypair.toJSON(false),
            sig: this.signatureKeypair.toJSON(false),
            tx: await this.transmitState.toJSON(false),
            rx: await this.receiveState.toJSON(false),
            pxk: this.peerExchangeKey.toJSON(false),
            psk: this.peerSignatureKey.toJSON(false),
            ptk: this.peerTemplateKey.toJSON(false),
            pik: this.peerIdentityKey?.toJSON(false),
            rsk: this.requestSecretKey.toJSON(false),
            typ: this.type,
            id: this.id,
            "@type": verbose ? "CryptoRelationshipSecretsHandle" : undefined
        };
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipSecretsHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoRelationshipSecretsHandle} and
     * interfaces conforming to {@link ICryptoRelationshipSecretsHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoRelationshipSecretsHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipSecretsHandle} instance.
     */
    public static async from(
        value: CryptoRelationshipSecretsHandle | ICryptoRelationshipSecretsHandle
    ): Promise<CryptoRelationshipSecretsHandle> {
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
                signatureKeypair: value.sig,
                transmitState: value.tx,
                receiveState: value.rx,
                peerExchangeKey: value.pxk,
                peerSignatureKey: value.psk,
                peerTemplateKey: value.ptk,
                peerIdentityKey: value.pik,
                requestSecretKey: value.rsk,
                type: value.typ,
                id: value.id
            };
        }
        return value;
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipSecretsHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoRelationshipSecretsHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipSecretsHandle} instance.
     */
    public static async fromJSON(
        value: ICryptoRelationshipSecretsHandleSerialized
    ): Promise<CryptoRelationshipSecretsHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoRelationshipSecretsHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoRelationshipSecretsHandle}.
     * @returns A Promise that resolves to a {@link CryptoRelationshipSecretsHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoRelationshipSecretsHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
