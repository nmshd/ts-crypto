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

    public override toJSON(verbose = true): ICryptoRelationshipPublicResponseSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            sta: this.state.toJSON(false),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicResponse" : undefined
        };
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
        return this.fromAny(value);
    }

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

    public static fromJSON(value: ICryptoRelationshipPublicResponseSerialized): CryptoRelationshipPublicResponse {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoRelationshipPublicResponse {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
