import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
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
import { CryptoPublicState, ICryptoPublicState, ICryptoPublicStateSerialized } from "../state/CryptoPublicState";

export interface ICryptoRelationshipPublicResponseSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangePublicKeySerialized;
    sig: ICryptoSignaturePublicKeySerialized;
    sta: ICryptoPublicStateSerialized;
}

export interface ICryptoRelationshipPublicResponse extends ISerializable {
    id?: string;
    exchangeKey: ICryptoExchangePublicKey;
    signatureKey: ICryptoSignaturePublicKey;
    state: ICryptoPublicState;
}

@type("CryptoRelationshipPublicResponse")
export class CryptoRelationshipPublicResponse
    extends CryptoSerializable
    implements ICryptoRelationshipPublicResponse, IClearable
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
    public state: CryptoPublicState;

    public constructor(
        signatureKey: CryptoSignaturePublicKey,
        exchangeKey: CryptoExchangePublicKey,
        state: CryptoPublicState
    ) {
        super();

        this.signatureKey = signatureKey;
        this.exchangeKey = exchangeKey;
        this.state = state;
    }

    public toJSON(verbose = true): ICryptoRelationshipPublicResponseSerialized {
        const obj: ICryptoRelationshipPublicResponseSerialized = {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            sta: this.state.toJSON(false)
        };
        if (verbose) {
            obj["@type"] = "CryptoRelationshipPublicResponse";
        }
        return obj;
    }

    public clear(): void {
        this.exchangeKey.clear();
        this.signatureKey.clear();
        this.state.clear();
    }

    public async verify(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.signatureKey);
    }

    public static from(
        value: CryptoRelationshipPublicResponse | ICryptoRelationshipPublicResponse
    ): CryptoRelationshipPublicResponse {
        const signatureKey = CryptoSignaturePublicKey.from(value.signatureKey);
        const exchangeKey = CryptoExchangePublicKey.from(value.exchangeKey);
        const state = CryptoPublicState.from(value.state);

        return new CryptoRelationshipPublicResponse(signatureKey, exchangeKey, state);
    }

    public static fromJSON(value: ICryptoRelationshipPublicResponseSerialized): CryptoRelationshipPublicResponse {
        const signatureKey = CryptoSignaturePublicKey.fromJSON(value.sig);
        const exchangeKey = CryptoExchangePublicKey.fromJSON(value.exc);
        const state = CryptoPublicState.fromJSON(value.sta);

        return new CryptoRelationshipPublicResponse(signatureKey, exchangeKey, state);
    }

    public static fromBase64(value: string): CryptoRelationshipPublicResponse {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoRelationshipPublicResponse {
        return this.fromJSON(JSON.parse(value));
    }
}
