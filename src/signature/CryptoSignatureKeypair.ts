import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
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
    public readonly publicKey: CryptoSignaturePublicKey;
    public readonly privateKey: CryptoSignaturePrivateKey;

    public constructor(publicKey: CryptoSignaturePublicKey, privateKey: CryptoSignaturePrivateKey) {
        const error = CryptoSignatureValidation.checkSignatureKeypair(privateKey, publicKey);
        if (error) throw error;

        super();

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public toJSON(verbose = true): ICryptoSignatureKeypairSerialized {
        const obj: ICryptoSignatureKeypairSerialized = {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false)
        };
        if (verbose) {
            obj["@type"] = "CryptoSignatureKeypair";
        }
        return obj;
    }

    public clear(): void {
        this.publicKey.clear();
        this.privateKey.clear();
    }

    public static from(value: CryptoSignatureKeypair | ICryptoSignatureKeypair): CryptoSignatureKeypair {
        const privateKey = CryptoSignaturePrivateKey.from(value.privateKey);
        const publicKey = CryptoSignaturePublicKey.from(value.publicKey);

        return new CryptoSignatureKeypair(publicKey, privateKey);
    }

    public static fromJSON(value: ICryptoSignatureKeypairSerialized): CryptoSignatureKeypair {
        const privateKey = CryptoSignaturePrivateKey.fromJSON(value.prv);
        const publicKey = CryptoSignaturePublicKey.fromJSON(value.pub);

        return new CryptoSignatureKeypair(publicKey, privateKey);
    }

    public static fromBase64(value: string): CryptoSignatureKeypair {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoSignatureKeypair {
        const obj = JSON.parse(value);
        return this.fromJSON(obj);
    }
}
