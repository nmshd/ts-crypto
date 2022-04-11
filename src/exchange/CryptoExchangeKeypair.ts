import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
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
    @validate()
    @serialize()
    public readonly publicKey: CryptoExchangePublicKey;

    @validate()
    @serialize()
    public readonly privateKey: CryptoExchangePrivateKey;

    public constructor(publicKey: CryptoExchangePublicKey, privateKey: CryptoExchangePrivateKey) {
        CryptoExchangeValidation.checkExchangeKeypair(privateKey, publicKey);

        super();

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public override toJSON(verbose = true): ICryptoExchangeKeypairSerialized {
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

    protected static override preFrom(value: any): any {
        if (value.pub) {
            value = {
                publicKey: value.pub,
                privateKey: value.prv
            };
        }

        CryptoExchangeValidation.checkExchangeKeypair(value.privateKey, value.publicKey);

        return value;
    }

    public static from(value: CryptoExchangeKeypair | ICryptoExchangeKeypair): CryptoExchangeKeypair {
        return this.fromAny(value);
    }

    public static fromJSON(value: ICryptoExchangeKeypairSerialized): CryptoExchangeKeypair {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoExchangeKeypair {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
