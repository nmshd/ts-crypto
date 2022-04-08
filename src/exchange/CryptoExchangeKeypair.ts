import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoSerializable } from "../CryptoSerializable";
import {
    CryptoExchangePrivateKey,
    ICryptoExchangePrivateKey,
    ICryptoExchangePrivateKeySerialized
} from "./CryptoExchangePrivateKey";
import {
    CryptoExchangePublicKey,
    ICryptoExchangePublicKey,
    ICryptoExchangePublicKeySerialized
} from "./CryptoExchangePublicKey";
import { CryptoExchangeValidation } from "./CryptoExchangeValidation";

export interface ICryptoExchangeKeypairSerialized extends ISerialized {
    pub: ICryptoExchangePublicKeySerialized;
    prv: ICryptoExchangePrivateKeySerialized;
}

export interface ICryptoExchangeKeypair extends ISerializable {
    publicKey: ICryptoExchangePublicKey;
    privateKey: ICryptoExchangePrivateKey;
}

@type("CryptoExchangeKeypair")
export class CryptoExchangeKeypair extends CryptoSerializable implements ICryptoExchangeKeypair, IClearable {
    public readonly publicKey: CryptoExchangePublicKey;
    public readonly privateKey: CryptoExchangePrivateKey;

    public constructor(publicKey: CryptoExchangePublicKey, privateKey: CryptoExchangePrivateKey) {
        CryptoExchangeValidation.checkExchangeKeypair(privateKey, publicKey);

        super();

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public toJSON(verbose = true): ICryptoExchangeKeypairSerialized {
        const obj: ICryptoExchangeKeypairSerialized = {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false)
        };
        if (verbose) {
            obj["@type"] = "CryptoExchangeKeypair";
        }

        return obj;
    }

    public clear(): void {
        this.publicKey.clear();
        this.privateKey.clear();
    }

    public static from(value: CryptoExchangeKeypair | ICryptoExchangeKeypair): CryptoExchangeKeypair {
        const privateKey = CryptoExchangePrivateKey.from(value.privateKey);
        const publicKey = CryptoExchangePublicKey.from(value.publicKey);

        return new CryptoExchangeKeypair(publicKey, privateKey);
    }

    public static fromJSON(value: ICryptoExchangeKeypairSerialized): CryptoExchangeKeypair {
        const privateKey = CryptoExchangePrivateKey.fromJSON(value.prv);
        const publicKey = CryptoExchangePublicKey.fromJSON(value.pub);

        return new CryptoExchangeKeypair(publicKey, privateKey);
    }

    public static fromBase64(value: string): CryptoExchangeKeypair {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoExchangeKeypair {
        const obj = JSON.parse(value);
        return this.fromJSON(obj);
    }
}
