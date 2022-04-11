import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoSerializable } from "../CryptoSerializable";
import {
    CryptoSignaturePrivateKey,
    ICryptoSignaturePrivateKey,
    ICryptoSignaturePrivateKeySerialized
} from "./CryptoSignaturePrivateKey";
import {
    CryptoSignaturePublicKey,
    ICryptoSignaturePublicKey,
    ICryptoSignaturePublicKeySerialized
} from "./CryptoSignaturePublicKey";
import { CryptoSignatureValidation } from "./CryptoSignatureValidation";

export interface ICryptoSignatureKeypairSerialized extends ISerialized {
    pub: ICryptoSignaturePublicKeySerialized;
    prv: ICryptoSignaturePrivateKeySerialized;
}

export interface ICryptoSignatureKeypair extends ISerializable {
    publicKey: ICryptoSignaturePublicKey;
    privateKey: ICryptoSignaturePrivateKey;
}

@type("CryptoSignatureKeypair")
export class CryptoSignatureKeypair extends CryptoSerializable implements ICryptoSignatureKeypair, IClearable {
    @validate()
    @serialize()
    public readonly publicKey: CryptoSignaturePublicKey;

    @validate()
    @serialize()
    public readonly privateKey: CryptoSignaturePrivateKey;

    public override toJSON(verbose = true): ICryptoSignatureKeypairSerialized {
        return {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false),
            "@type": verbose ? "CryptoSignatureKeypair" : undefined
        };
    }

    public clear(): void {
        this.publicKey.clear();
        this.privateKey.clear();
    }

    public static from(value: CryptoSignatureKeypair | ICryptoSignatureKeypair): CryptoSignatureKeypair {
        return this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.pub) {
            value = {
                publicKey: value.pub,
                privateKey: value.prv
            };
        }

        CryptoSignatureValidation.checkSignatureKeypair(value.privateKey, value.publicKey);

        return value;
    }

    public static fromJSON(value: ICryptoSignatureKeypairSerialized): CryptoSignatureKeypair {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoSignatureKeypair {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
