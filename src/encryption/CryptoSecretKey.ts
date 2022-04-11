import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
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
        CryptoValidation.checkSerializedSecretKeyForAlgorithm(
            value.secretKey,
            value.algorithm as CryptoEncryptionAlgorithm
        );

        return value;
    }

    public static fromJSON(value: ICryptoSecretKeySerialized): CryptoSecretKey {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoSecretKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
