import { ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoPublicKey } from "../CryptoPublicKey";
import { CryptoExchangeAlgorithm } from "./CryptoExchange";
import { CryptoExchangeValidation } from "./CryptoExchangeValidation";

export interface ICryptoExchangePublicKeySerialized extends ISerialized {
    alg: number;
    pub: string;
}

export interface ICryptoExchangePublicKey {
    algorithm: CryptoExchangeAlgorithm;
    publicKey: CoreBuffer;
}

@type("CryptoExchangePublicKey")
export class CryptoExchangePublicKey extends CryptoPublicKey implements ICryptoExchangePublicKey, IClearable {
    @validate()
    @serialize()
    public override algorithm: CryptoExchangeAlgorithm;

    @validate()
    @serialize()
    public override publicKey: CoreBuffer;

    public override toJSON(verbose = true): ICryptoExchangePublicKeySerialized {
        return {
            "@type": verbose ? "CryptoExchangePublicKey" : undefined,
            pub: this.publicKey.toBase64URL(),
            alg: this.algorithm
        };
    }

    public clear(): void {
        this.publicKey.clear();
    }

    protected static override preFrom(value: any): any {
        if (value.alg) {
            value = {
                algorithm: value.alg,
                publicKey: value.pub
            };
        }

        CryptoExchangeValidation.checkExchangeAlgorithm(value.algorithm);
        CryptoExchangeValidation.checkExchangePublicKey(value.publicKey, value.algorithm);

        return value;
    }

    public static override from(value: CryptoExchangePublicKey | ICryptoExchangePublicKey): CryptoExchangePublicKey {
        return this.fromAny(value);
    }

    public static fromJSON(value: ICryptoExchangePublicKeySerialized): CryptoExchangePublicKey {
        return this.fromAny(value);
    }

    public static override fromBase64(value: string): CryptoExchangePublicKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
