import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm } from "./CryptoEncryption";

export interface ICryptoCipherSerialized extends ISerialized {
    alg: number;
    cph: string;
    cnt?: number;
    nnc?: string;
}

export interface ICryptoCipher extends ISerializable {
    algorithm: CryptoEncryptionAlgorithm;
    cipher: ICoreBuffer;
    counter?: number;
    nonce?: ICoreBuffer;
}

@type("CryptoCipher")
export class CryptoCipher extends CryptoSerializable implements ICryptoCipher, IClearable {
    public static MIN_CIPHER_BYTES = 2;
    public static MAX_CIPHER_BYTES = 100 * 1024 * 1024;

    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public cipher: CoreBuffer;

    @validate({ nullable: true })
    @serialize()
    public counter?: number;

    @validate({ nullable: true })
    @serialize()
    public nonce?: CoreBuffer;

    public override toJSON(verbose = true): ICryptoCipherSerialized {
        return {
            cph: this.cipher.toBase64URL(),
            alg: this.algorithm,
            nnc: this.nonce ? this.nonce.toBase64URL() : undefined,
            cnt: this.counter,
            "@type": verbose ? "CryptoCipher" : undefined
        };
    }

    public clear(): void {
        this.cipher.clear();
        this.nonce?.clear();
    }

    public static from(value: CryptoCipher | ICryptoCipher): CryptoCipher {
        return this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.cph) {
            value = {
                cipher: value.cph,
                algorithm: value.alg,
                nonce: value.nnc,
                counter: value.cnt
            };
        }

        if (!value.nonce && typeof value.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.EncryptionNoNonceNorCounter, "No nonce nor counter property set.");
        }
        if (value.nonce && typeof value.counter !== "undefined") {
            throw new CryptoError(CryptoErrorCode.EncryptionNonceAndCounter, "Nonce and counter properties are set.");
        }

        if (typeof value.cipher === "string") {
            CryptoValidation.checkSerializedBuffer(
                value.cipher,
                this.MIN_CIPHER_BYTES,
                this.MAX_CIPHER_BYTES,
                "cipher"
            );
        } else {
            CryptoValidation.checkBuffer(
                value.cipher,
                CryptoCipher.MIN_CIPHER_BYTES,
                CryptoCipher.MAX_CIPHER_BYTES,
                "cipher"
            );
        }

        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);

        if (value.counter) {
            CryptoValidation.checkCounter(value.counter);
        }
        if (value.nonce) {
            CryptoValidation.checkNonce(value.nonce, value.algorithm);
        }

        return value;
    }

    public static fromJSON(value: ICryptoCipherSerialized): CryptoCipher {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoCipher {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
