import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoPrivateKey } from "../CryptoPrivateKey";
import { CryptoExchange, CryptoExchangeAlgorithm } from "./CryptoExchange";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeValidation } from "./CryptoExchangeValidation";

export interface ICryptoExchangePrivateKeySerialized extends ISerialized {
    alg: number;
    prv: string;
}

export interface ICryptoExchangePrivateKey extends ISerializable {
    algorithm: CryptoExchangeAlgorithm;
    privateKey: ICoreBuffer;
}

@type("CryptoExchangePrivateKey")
export class CryptoExchangePrivateKey extends CryptoPrivateKey implements ICryptoExchangePrivateKey, IClearable {
    public readonly algorithm: CryptoExchangeAlgorithm;
    public readonly privateKey: CoreBuffer;

    public constructor(algorithm: CryptoExchangeAlgorithm, privateKey: CoreBuffer) {
        CryptoExchangeValidation.checkExchangeAlgorithm(algorithm);
        CryptoExchangeValidation.checkExchangePrivateKeyAsBuffer(privateKey, algorithm);

        super(algorithm, privateKey);

        this.algorithm = algorithm;
        this.privateKey = privateKey;
    }

    public toJSON(verbose = true): ICryptoExchangePrivateKeySerialized {
        const obj: ICryptoExchangePrivateKeySerialized = {
            prv: this.privateKey.toBase64URL(),
            alg: this.algorithm
        };
        if (verbose) {
            obj["@type"] = "CryptoExchangePrivateKey";
        }
        return obj;
    }

    public clear(): void {
        this.privateKey.clear();
    }

    public serialize(verbose = true): string {
        return JSON.stringify(this.toJSON(verbose));
    }

    public toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public async toPublicKey(): Promise<CryptoExchangePublicKey> {
        return await CryptoExchange.privateKeyToPublicKey(this);
    }

    public static from(value: CryptoExchangePrivateKey | ICryptoExchangePrivateKey): CryptoExchangePrivateKey {
        return new CryptoExchangePrivateKey(value.algorithm, CoreBuffer.from(value.privateKey));
    }

    public static fromJSON(value: ICryptoExchangePrivateKeySerialized): CryptoExchangePrivateKey {
        CryptoExchangeValidation.checkExchangeAlgorithm(value.alg);
        CryptoExchangeValidation.checkExchangePrivateKeyAsNumber(
            value.prv,
            value.alg as CryptoExchangeAlgorithm,
            "privateKey"
        );

        const buffer = CoreBuffer.fromBase64URL(value.prv);
        return new CryptoExchangePrivateKey(value.alg as CryptoExchangeAlgorithm, buffer);
    }

    public static fromBase64(value: string): CryptoExchangePrivateKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoExchangePrivateKey {
        return this.fromJSON(JSON.parse(value));
    }
}
