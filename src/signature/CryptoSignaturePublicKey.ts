import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoPublicKey } from "../CryptoPublicKey";
import { CryptoSignatureAlgorithm } from "./CryptoSignatures";
import { CryptoSignatureValidation } from "./CryptoSignatureValidation";

export interface ICryptoSignaturePublicKeySerialized extends ISerialized {
    alg: number;
    pub: string;
}

export interface ICryptoSignaturePublicKey extends ISerializable {
    algorithm: CryptoSignatureAlgorithm;
    publicKey: ICoreBuffer;
}

@type("CryptoSignaturePublicKey")
export class CryptoSignaturePublicKey extends CryptoPublicKey implements ICryptoSignaturePublicKey, IClearable {
    public readonly algorithm: CryptoSignatureAlgorithm;
    public readonly publicKey: CoreBuffer;

    public constructor(algorithm: CryptoSignatureAlgorithm, publicKey: CoreBuffer) {
        CryptoSignatureValidation.checkSignatureAlgorithm(algorithm);
        CryptoSignatureValidation.checkSignaturePublicKeyAsBuffer(publicKey, algorithm);

        super(algorithm, publicKey);

        this.algorithm = algorithm;
        this.publicKey = publicKey;
    }

    public toJSON(verbose = true): ICryptoSignaturePublicKeySerialized {
        const obj: ICryptoSignaturePublicKeySerialized = {
            pub: this.publicKey.toBase64URL(),
            alg: this.algorithm
        };
        if (verbose) {
            obj["@type"] = "CryptoSignaturePublicKey";
        }
        return obj;
    }

    public clear(): void {
        this.publicKey.clear();
    }

    public serialize(verbose = true): string {
        return JSON.stringify(this.toJSON(verbose));
    }

    public toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public static from(value: CryptoSignaturePublicKey | ICryptoSignaturePublicKey): CryptoSignaturePublicKey {
        return new CryptoSignaturePublicKey(value.algorithm, CoreBuffer.from(value.publicKey));
    }

    public static fromJSON(value: ICryptoSignaturePublicKeySerialized): CryptoSignaturePublicKey {
        let error;
        error = CryptoSignatureValidation.checkSignatureAlgorithm(value.alg);
        if (error) throw error;

        error = CryptoSignatureValidation.checkSignaturePublicKeyAsString(
            value.pub,
            value.alg as CryptoSignatureAlgorithm,
            "publicKey"
        );
        if (error) throw error;

        const buffer = CoreBuffer.fromBase64URL(value.pub);
        return this.from({
            algorithm: value.alg as CryptoSignatureAlgorithm,
            publicKey: buffer
        });
    }

    public static fromBase64(value: string): CryptoSignaturePublicKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoSignaturePublicKey {
        const obj = JSON.parse(value);
        return this.fromJSON(obj);
    }
}
