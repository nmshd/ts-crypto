import { ISerialized, type } from "@js-soft/ts-serval";
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
    public readonly algorithm: CryptoExchangeAlgorithm;
    public readonly publicKey: CoreBuffer;

    public constructor(algorithm: CryptoExchangeAlgorithm, publicKey: CoreBuffer) {
        CryptoExchangeValidation.checkExchangeAlgorithm(algorithm);
        CryptoExchangeValidation.checkExchangePublicKeyAsBuffer(publicKey, algorithm);

        super(algorithm, publicKey);

        this.algorithm = algorithm;
        this.publicKey = publicKey;
    }

    public toJSON(verbose = true): ICryptoExchangePublicKeySerialized {
        const obj: ICryptoExchangePublicKeySerialized = {
            pub: this.publicKey.toBase64URL(),
            alg: this.algorithm
        };
        if (verbose) {
            obj["@type"] = "CryptoExchangePublicKey";
        }
        return obj;
    }

    public clear(): void {
        this.publicKey.clear();
    }

    public static from(value: CryptoExchangePublicKey | ICryptoExchangePublicKey): Promise<CryptoExchangePublicKey> {
        return Promise.resolve(new CryptoExchangePublicKey(value.algorithm, value.publicKey));
    }

    public static async fromJSON(value: ICryptoExchangePublicKeySerialized): Promise<CryptoExchangePublicKey> {
        CryptoExchangeValidation.checkExchangeAlgorithm(value.alg);
        CryptoExchangeValidation.checkExchangePrivateKeyAsNumber(
            value.pub,
            value.alg as CryptoExchangeAlgorithm,
            "publicKey"
        );

        const buffer = CoreBuffer.fromBase64URL(value.pub);
        return await this.from({
            algorithm: value.alg as CryptoExchangeAlgorithm,
            publicKey: buffer
        });
    }

    public static async fromBase64(value: string): Promise<CryptoExchangePublicKey> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoExchangePublicKey> {
        const obj = JSON.parse(value);
        return await this.fromJSON(obj);
    }
}
