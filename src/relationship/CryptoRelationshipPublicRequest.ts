import { ISerializableAsync, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSerializableAsync } from "../CryptoSerializableAsync";
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

export interface ICryptoRelationshipPublicRequest extends ISerializableAsync {
    id?: string;
    exchangeKey: ICryptoExchangePublicKey;
    signatureKey: ICryptoSignaturePublicKey;
    ephemeralKey: ICryptoExchangePublicKey;
    nonce: ICoreBuffer;
}

@type("CryptoRelationshipPublicRequest")
export class CryptoRelationshipPublicRequest
    extends CryptoSerializableAsync
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

    public static async from(
        value: CryptoRelationshipPublicRequest | ICryptoRelationshipPublicRequest
    ): Promise<CryptoRelationshipPublicRequest> {
        const [signatureKey, exchangeKey, ephemeralKey, nonce] = await Promise.all([
            CryptoSignaturePublicKey.from(value.signatureKey),
            CryptoExchangePublicKey.from(value.exchangeKey),
            CryptoExchangePublicKey.from(value.ephemeralKey),
            CoreBuffer.from(value.nonce)
        ]);
        return new CryptoRelationshipPublicRequest(signatureKey, exchangeKey, ephemeralKey, nonce);
    }

    public static async fromJSON(
        value: ICryptoRelationshipPublicRequestSerialized
    ): Promise<CryptoRelationshipPublicRequest> {
        const [signatureKey, exchangeKey, ephemeralKey, nonce] = await Promise.all([
            CryptoSignaturePublicKey.fromJSON(value.sig),
            CryptoExchangePublicKey.fromJSON(value.exc),
            CryptoExchangePublicKey.fromJSON(value.eph),
            CoreBuffer.fromBase64URL(value.nnc)
        ]);

        return new CryptoRelationshipPublicRequest(signatureKey, exchangeKey, ephemeralKey, nonce);
    }

    public static async fromBase64(value: string): Promise<CryptoRelationshipPublicRequest> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoRelationshipPublicRequest> {
        return await this.fromJSON(JSON.parse(value));
    }
}
