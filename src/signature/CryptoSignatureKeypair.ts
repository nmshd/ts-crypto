import { ISerializableAsync, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoSerializableAsync } from "../CryptoSerializableAsync";
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

export interface ICryptoSignatureKeypair extends ISerializableAsync {
    publicKey: ICryptoSignaturePublicKey;
    privateKey: ICryptoSignaturePrivateKey;
}

@type("CryptoSignatureKeypair")
export class CryptoSignatureKeypair extends CryptoSerializableAsync implements ICryptoSignatureKeypair, IClearable {
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

    public static async from(value: CryptoSignatureKeypair | ICryptoSignatureKeypair): Promise<CryptoSignatureKeypair> {
        const [privateKey, publicKey] = await Promise.all([
            CryptoSignaturePrivateKey.from(value.privateKey),
            CryptoSignaturePublicKey.from(value.publicKey)
        ]);

        return new CryptoSignatureKeypair(publicKey, privateKey);
    }

    public static async fromJSON(value: ICryptoSignatureKeypairSerialized): Promise<CryptoSignatureKeypair> {
        const [privateKey, publicKey] = await Promise.all([
            CryptoSignaturePrivateKey.fromJSON(value.prv),
            CryptoSignaturePublicKey.fromJSON(value.pub)
        ]);

        return new CryptoSignatureKeypair(publicKey, privateKey);
    }

    public static async fromBase64(value: string): Promise<CryptoSignatureKeypair> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoSignatureKeypair> {
        const obj = JSON.parse(value);
        return await this.fromJSON(obj);
    }
}
