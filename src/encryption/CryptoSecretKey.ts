import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSerializable } from "../CryptoSerializable";
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
export class CryptoSecretKey extends CryptoSerializable implements ICryptoSecretKey, IClearable {
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;
    @validate()
    @serialize()
    public secretKey: CoreBuffer;

    public override toJSON(verbose = true): ICryptoSecretKeySerialized {
        return {
            key: this.secretKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoSecretKey" : undefined
        };
    }

    public clear(): void {
        this.secretKey.clear();
    }

    public static from(value: CryptoSecretKey | ICryptoSecretKey): CryptoSecretKey {
        return this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.alg) {
            value = {
                algorithm: value.alg,
                secretKey: value.key
            };
        }

        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);

        if (typeof value.secretKey === "string") {
            CryptoValidation.checkSerializedSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        } else {
            CryptoValidation.checkSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        }

        return value;
    }

    public static fromJSON(value: ICryptoSecretKeySerialized): CryptoSecretKey {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoSecretKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
