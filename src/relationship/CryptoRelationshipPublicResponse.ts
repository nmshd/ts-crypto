import { ISerializableAsync, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoSerializableAsync } from "../CryptoSerializableAsync";
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

export interface ICryptoRelationshipPublicResponse extends ISerializableAsync {
    id?: string;
    exchangeKey: ICryptoExchangePublicKey;
    signatureKey: ICryptoSignaturePublicKey;
    state: ICryptoPublicState;
}

@type("CryptoRelationshipPublicResponse")
export class CryptoRelationshipPublicResponse
    extends CryptoSerializableAsync
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

    public static async from(
        value: CryptoRelationshipPublicResponse | ICryptoRelationshipPublicResponse
    ): Promise<CryptoRelationshipPublicResponse> {
        const [signatureKey, exchangeKey, state] = await Promise.all([
            CryptoSignaturePublicKey.from(value.signatureKey),
            CryptoExchangePublicKey.from(value.exchangeKey),
            CryptoPublicState.from(value.state)
        ]);
        return new CryptoRelationshipPublicResponse(signatureKey, exchangeKey, state);
    }

    public static async fromJSON(
        value: ICryptoRelationshipPublicResponseSerialized
    ): Promise<CryptoRelationshipPublicResponse> {
        const [signatureKey, exchangeKey, state] = await Promise.all([
            CryptoSignaturePublicKey.fromJSON(value.sig),
            CryptoExchangePublicKey.fromJSON(value.exc),
            CryptoPublicState.fromJSON(value.sta)
        ]);

        return new CryptoRelationshipPublicResponse(signatureKey, exchangeKey, state);
    }

    public static async fromBase64(value: string): Promise<CryptoRelationshipPublicResponse> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoRelationshipPublicResponse> {
        return await this.fromJSON(JSON.parse(value));
    }
}
