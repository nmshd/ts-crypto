import { ISerializableAsync, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoPrivateKey } from "../CryptoPrivateKey";
import { CryptoSignaturePublicKey } from "./CryptoSignaturePublicKey";
import { CryptoSignatureAlgorithm, CryptoSignatures } from "./CryptoSignatures";
import { CryptoSignatureValidation } from "./CryptoSignatureValidation";

export interface ICryptoSignaturePrivateKeySerialized extends ISerialized {
    alg: number;
    prv: string;
    id?: string;
}
export interface ICryptoSignaturePrivateKey extends ISerializableAsync {
    algorithm: CryptoSignatureAlgorithm;
    privateKey: ICoreBuffer;
    id?: string;
}

@type("CryptoSignaturePrivateKey")
export class CryptoSignaturePrivateKey extends CryptoPrivateKey implements ICryptoSignaturePrivateKey, IClearable {
    public readonly algorithm: CryptoSignatureAlgorithm;
    public readonly privateKey: CoreBuffer;
    public readonly id?: string;

    public constructor(algorithm: CryptoSignatureAlgorithm, privateKey: CoreBuffer, id?: string) {
        CryptoSignatureValidation.checkSignatureAlgorithm(algorithm);
        CryptoSignatureValidation.checkSignaturePrivateKeyAsBuffer(privateKey);

        super(algorithm, privateKey);

        this.algorithm = algorithm;
        this.privateKey = privateKey;
        this.id = id;
    }

    public toJSON(verbose = true): ICryptoSignaturePrivateKeySerialized {
        const obj: ICryptoSignaturePrivateKeySerialized = {
            prv: this.privateKey.toBase64URL(),
            alg: this.algorithm
        };
        if (verbose) {
            obj["@type"] = "CryptoSignaturePrivateKey";
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

    public async toPublicKey(): Promise<CryptoSignaturePublicKey> {
        return await CryptoSignatures.privateKeyToPublicKey(this);
    }

    public static from(
        value: CryptoSignaturePrivateKey | ICryptoSignaturePrivateKey
    ): Promise<CryptoSignaturePrivateKey> {
        return Promise.resolve(new CryptoSignaturePrivateKey(value.algorithm, CoreBuffer.from(value.privateKey)));
    }

    public static fromJSON(value: ICryptoSignaturePrivateKeySerialized): Promise<CryptoSignaturePrivateKey> {
        let error;

        error = CryptoSignatureValidation.checkSignatureAlgorithm(value.alg);
        if (error) throw error;

        error = CryptoSignatureValidation.checkSignaturePrivateKeyAsString(value.prv, "privateKey");
        if (error) throw error;

        const buffer = CoreBuffer.fromBase64URL(value.prv);
        return Promise.resolve(new CryptoSignaturePrivateKey(value.alg as CryptoSignatureAlgorithm, buffer));
    }

    public static async fromBase64(value: string): Promise<CryptoSignaturePrivateKey> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoSignaturePrivateKey> {
        return await this.fromJSON(JSON.parse(value));
    }
}
