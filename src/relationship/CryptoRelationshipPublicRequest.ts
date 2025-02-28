import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CryptoRelationshipPublicRequestHandle } from "src/crypto-layer/relationship/CryptoRelationshipRequestSecretsHandle";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import {
    CryptoExchangePublicKeyHandle,
    ICryptoExchangePublicKeyHandleSerialized
} from "../crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import {
    CryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandleSerialized
} from "../crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import {
    CryptoExchangePublicKey,
    ICryptoExchangePublicKey,
    ICryptoExchangePublicKeySerialized
} from "../exchange/CryptoExchangePublicKey";
import { CryptoSignature } from "../signature/CryptoSignature";
import {
    CryptoSignaturePublicKey,
    ICryptoSignaturePublicKey,
    ICryptoSignaturePublicKeySerialized
} from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";

export interface ICryptoRelationshipPublicRequestSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangePublicKeyHandleSerialized | ICryptoExchangePublicKeySerialized;
    sig: ICryptoSignaturePublicKeyHandleSerialized | ICryptoSignaturePublicKeySerialized;
    eph: ICryptoExchangePublicKeyHandleSerialized | ICryptoExchangePublicKeySerialized;
    nnc: string;
}

export interface ICryptoRelationshipPublicRequest extends ISerializable {
    id?: string;
    exchangeKey: ICryptoExchangePublicKey | CryptoExchangePublicKeyHandle;
    signatureKey: ICryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;
    ephemeralKey: ICryptoExchangePublicKey | CryptoExchangePublicKeyHandle;
    nonce: ICoreBuffer;
}

@type("CryptoRelationshipPublicRequest")
export class CryptoRelationshipPublicRequest
    extends CryptoSerializable
    implements ICryptoRelationshipPublicRequest, IClearable
{
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle;

    @validate()
    @serialize()
    public ephemeralKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    public override toJSON(verbose = true): ICryptoRelationshipPublicRequestSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            eph: this.ephemeralKey.toJSON(false),
            nnc: this.nonce.toBase64URL(),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicRequest" : undefined
        };
    }

    public clear(): void {
        if (this.exchangeKey instanceof CryptoExchangePublicKey) {
            this.exchangeKey.clear();
        }
        if (this.signatureKey instanceof CryptoSignaturePublicKey) {
            this.signatureKey.clear();
        }
        if (this.ephemeralKey instanceof CryptoExchangePublicKey) {
            this.ephemeralKey.clear();
        }
        this.nonce.clear();
    }

    /**
     * Determines if this request is using the crypto-layer implementation
     * @returns True if using CAL, false if using libsodium
     */
    public isUsingCryptoLayer(): boolean {
        return (
            this.exchangeKey instanceof CryptoExchangePublicKeyHandle &&
            this.signatureKey instanceof CryptoSignaturePublicKeyHandle &&
            this.ephemeralKey instanceof CryptoExchangePublicKeyHandle
        );
    }

    /**
     * Verifies content with the signature key included in this request
     * @param content Content to verify
     * @param signature Signature to verify
     * @returns Promise resolving to true if verified, false otherwise
     */
    public async verify(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.signatureKey);
    }

    /**
     * Converts this request to a CAL handle
     * @returns A promise resolving to a CAL request handle
     */
    public async toHandle(): Promise<CryptoRelationshipPublicRequestHandle> {
        // If we're already using CAL-compatible keys
        if (
            this.exchangeKey instanceof CryptoExchangePublicKeyHandle &&
            this.signatureKey instanceof CryptoSignaturePublicKeyHandle &&
            this.ephemeralKey instanceof CryptoExchangePublicKeyHandle
        ) {
            return await CryptoRelationshipPublicRequestHandle.from({
                id: this.id,
                exchangeKey: this.exchangeKey,
                signatureKey: this.signatureKey,
                ephemeralKey: this.ephemeralKey,
                nonce: this.nonce
            });
        }

        throw new CryptoError(
            CryptoErrorCode.CalUninitializedKey,
            "Cannot create handle: this request doesn't use crypto-layer key handles"
        );
    }

    public static from(
        value: CryptoRelationshipPublicRequest | ICryptoRelationshipPublicRequest
    ): CryptoRelationshipPublicRequest {
        return this.fromAny(value);
    }

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

    public static fromJSON(value: ICryptoRelationshipPublicRequestSerialized): CryptoRelationshipPublicRequest {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoRelationshipPublicRequest {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Creates a relationship request from a CAL handle
     * @param handle The CAL handle to convert from
     * @returns A promise resolving to a relationship request
     */
    public static async fromHandle(
        handle: CryptoRelationshipPublicRequestHandle
    ): Promise<CryptoRelationshipPublicRequest> {
        return CryptoRelationshipPublicRequest.from({
            id: handle.id,
            exchangeKey: handle.exchangeKey,
            signatureKey: handle.signatureKey,
            ephemeralKey: handle.ephemeralKey,
            nonce: handle.nonce
        });
    }
}
