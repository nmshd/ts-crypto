import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSerializableAsync } from "../CryptoSerializableAsync";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm } from "./CryptoEncryption";

export interface ICryptoSecretKeySerialized extends ISerialized {
    alg: number;
    key: string;
}

export interface ICryptoSecretKey extends ISerializable {
    algorithm: CryptoEncryptionAlgorithm;
    secretKey: ICoreBuffer;
}

@type("CryptoSecretKey")
export class CryptoSecretKey extends CryptoSerializableAsync implements ICryptoSecretKey, IClearable {
    public readonly algorithm: CryptoEncryptionAlgorithm;
    public readonly secretKey: CoreBuffer;

    public constructor(
        secretKey: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ) {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);
        CryptoValidation.checkSecretKeyForAlgorithm(secretKey, algorithm);

        super();

        this.algorithm = algorithm;
        this.secretKey = secretKey;
    }

    public toJSON(verbose = true): ICryptoSecretKeySerialized {
        const obj: ICryptoSecretKeySerialized = {
            key: this.secretKey.toBase64URL(),
            alg: this.algorithm
        };
        if (verbose) {
            obj["@type"] = "CryptoSecretKey";
        }
        return obj;
    }

    public clear(): void {
        this.secretKey.clear();
    }

    public static from(value: CryptoSecretKey | ICryptoSecretKey): Promise<CryptoSecretKey> {
        return Promise.resolve(new CryptoSecretKey(CoreBuffer.from(value.secretKey), value.algorithm));
    }

    public static async fromJSON(value: ICryptoSecretKeySerialized): Promise<CryptoSecretKey> {
        CryptoValidation.checkEncryptionAlgorithm(value.alg);
        CryptoValidation.checkSerializedSecretKeyForAlgorithm(value.key, value.alg as CryptoEncryptionAlgorithm);

        const buffer = CoreBuffer.fromBase64URL(value.key);
        return await this.from({
            algorithm: value.alg as CryptoEncryptionAlgorithm,
            secretKey: buffer
        });
    }

    public static fromBase64(value: string): Promise<CryptoSecretKey> {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoSecretKey> {
        const obj = JSON.parse(value);
        return await this.fromJSON(obj);
    }
}
