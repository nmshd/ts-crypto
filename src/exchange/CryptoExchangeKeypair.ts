import { ISerializableAsync, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoSerializableAsync } from "../CryptoSerializableAsync";
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

export interface ICryptoExchangeKeypair extends ISerializableAsync {
    publicKey: ICryptoExchangePublicKey;
    privateKey: ICryptoExchangePrivateKey;
}

@type("CryptoExchangeKeypair")
export class CryptoExchangeKeypair extends CryptoSerializableAsync implements ICryptoExchangeKeypair, IClearable {
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

    public static async from(value: CryptoExchangeKeypair | ICryptoExchangeKeypair): Promise<CryptoExchangeKeypair> {
        const [privateKey, publicKey] = await Promise.all([
            CryptoExchangePrivateKey.from(value.privateKey),
            CryptoExchangePublicKey.from(value.publicKey)
        ]);

        return new CryptoExchangeKeypair(publicKey, privateKey);
    }

    public static async fromJSON(value: ICryptoExchangeKeypairSerialized): Promise<CryptoExchangeKeypair> {
        const [privateKey, publicKey] = await Promise.all([
            CryptoExchangePrivateKey.fromJSON(value.prv),
            CryptoExchangePublicKey.fromJSON(value.pub)
        ]);

        return new CryptoExchangeKeypair(publicKey, privateKey);
    }

    public static async fromBase64(value: string): Promise<CryptoExchangeKeypair> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoExchangeKeypair> {
        const obj = JSON.parse(value);
        return await this.fromJSON(obj);
    }
}
