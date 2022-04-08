import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
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

    public readonly algorithm: CryptoEncryptionAlgorithm;
    public readonly cipher: CoreBuffer;
    public readonly counter?: number;
    public readonly nonce?: CoreBuffer;

    public constructor(cipher: CoreBuffer, algorithm: CryptoEncryptionAlgorithm, nonce?: CoreBuffer, counter?: number) {
        if (!nonce && typeof counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.EncryptionNoNonceNorCounter, "No nonce nor counter property set.");
        }
        if (nonce && typeof counter !== "undefined") {
            throw new CryptoError(CryptoErrorCode.EncryptionNonceAndCounter, "Nonce and counter properties are set.");
        }

        CryptoValidation.checkBuffer(cipher, CryptoCipher.MIN_CIPHER_BYTES, CryptoCipher.MAX_CIPHER_BYTES, "cipher");
        CryptoValidation.checkEncryptionAlgorithm(algorithm);

        if (typeof counter !== "undefined") {
            CryptoValidation.checkCounter(counter);
        }
        if (typeof nonce !== "undefined") {
            CryptoValidation.checkNonceForAlgorithm(nonce, algorithm);
        }

        super();

        this.cipher = cipher;
        this.nonce = nonce;
        this.counter = counter;
        this.algorithm = algorithm;
    }

    public toJSON(verbose = true): ICryptoCipherSerialized {
        const obj: ICryptoCipherSerialized = {
            cph: this.cipher.toBase64URL(),
            alg: this.algorithm
        };
        if (this.nonce) {
            obj.nnc = this.nonce.toBase64URL();
        }
        if (typeof this.counter !== "undefined") {
            obj.cnt = this.counter;
        }
        if (verbose) {
            obj["@type"] = "CryptoCipher";
        }
        return obj;
    }

    public clear(): void {
        this.cipher.clear();
        if (this.nonce) this.nonce.clear();
    }

    public static from(value: CryptoCipher | ICryptoCipher): CryptoCipher {
        return new CryptoCipher(
            CoreBuffer.from(value.cipher),
            value.algorithm,
            CoreBuffer.from(value.nonce),
            value.counter
        );
    }

    public static fromJSON(value: ICryptoCipherSerialized): CryptoCipher {
        CryptoValidation.checkObject(value);
        CryptoValidation.checkEncryptionAlgorithm(value.alg);

        let nonceBuffer;
        let counter;
        if (typeof value.nnc !== "undefined") {
            CryptoValidation.checkSerializedBuffer(value.nnc, 12, 32, "nonce");
            nonceBuffer = CoreBuffer.fromBase64URL(value.nnc);
        }

        if (typeof value.cnt !== "undefined") {
            CryptoValidation.checkCounter(value.cnt);
            counter = value.cnt;
        }

        CryptoValidation.checkSerializedBuffer(value.cph, this.MIN_CIPHER_BYTES, this.MAX_CIPHER_BYTES, "cipher");

        const cipherBuffer = CoreBuffer.fromBase64URL(value.cph);
        return new CryptoCipher(cipherBuffer, value.alg as CryptoEncryptionAlgorithm, nonceBuffer, counter);
    }

    public static fromBase64(value: string): CryptoCipher {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoCipher {
        const obj = JSON.parse(value);
        return this.fromJSON(obj);
    }
}
