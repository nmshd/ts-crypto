import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
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
    public publicKey: CryptoExchangePublicKey;

    @validate()
    @serialize()
    public privateKey: CryptoExchangePrivateKey;

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

        if (value.privateKey.algorithm !== value.publicKey.algorithm) {
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                "Algorithms of private and public key do not match."
            );
        }

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
