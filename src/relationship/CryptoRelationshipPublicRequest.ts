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

export interface ICryptoRelationshipPublicRequestSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangePublicKeySerialized;
    sig: ICryptoSignaturePublicKeySerialized;
    eph: ICryptoExchangePublicKeySerialized;
    nnc: string;
}

export interface ICryptoRelationshipPublicRequest extends ISerializable {
    id?: string;
    exchangeKey: ICryptoExchangePublicKey;
    signatureKey: ICryptoSignaturePublicKey;
    ephemeralKey: ICryptoExchangePublicKey;
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

    public override toJSON(verbose = true): ICryptoRelationshipPublicRequestSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            eph: this.ephemeralKey.toJSON(false),
            nnc: this.nonce.toBase64URL(),
            "@type": verbose ? "CryptoRelationshipPublicRequest" : undefined
        };
    }

    public clear(): void {
        this.exchangeKey.clear();
        this.signatureKey.clear();
        this.ephemeralKey.clear();
        this.nonce.clear();
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
                nonce: value.nnc
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
}
