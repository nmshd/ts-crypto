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

    public constructor(
        signatureKey: CryptoSignaturePublicKey,
        exchangeKey: CryptoExchangePublicKey,
        ephemeralKey: CryptoExchangePublicKey,
        nonce: CoreBuffer
    ) {
        super();

        this.signatureKey = signatureKey;
        this.exchangeKey = exchangeKey;
        this.ephemeralKey = ephemeralKey;
        this.nonce = nonce;
    }

    public toJSON(verbose = true): ICryptoRelationshipPublicRequestSerialized {
        const obj: ICryptoRelationshipPublicRequestSerialized = {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            eph: this.ephemeralKey.toJSON(false),
            nnc: this.nonce.toBase64URL()
        };
        if (verbose) {
            obj["@type"] = "CryptoRelationshipPublicRequest";
        }
        return obj;
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
        const signatureKey = CryptoSignaturePublicKey.from(value.signatureKey);
        const exchangeKey = CryptoExchangePublicKey.from(value.exchangeKey);
        const ephemeralKey = CryptoExchangePublicKey.from(value.ephemeralKey);
        const nonce = CoreBuffer.from(value.nonce);

        return new CryptoRelationshipPublicRequest(signatureKey, exchangeKey, ephemeralKey, nonce);
    }

    public static fromJSON(value: ICryptoRelationshipPublicRequestSerialized): CryptoRelationshipPublicRequest {
        const signatureKey = CryptoSignaturePublicKey.fromJSON(value.sig);
        const exchangeKey = CryptoExchangePublicKey.fromJSON(value.exc);
        const ephemeralKey = CryptoExchangePublicKey.fromJSON(value.eph);
        const nonce = CoreBuffer.fromBase64URL(value.nnc);

        return new CryptoRelationshipPublicRequest(signatureKey, exchangeKey, ephemeralKey, nonce);
    }

    public static fromBase64(value: string): CryptoRelationshipPublicRequest {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoRelationshipPublicRequest {
        return this.fromJSON(JSON.parse(value));
    }
}
