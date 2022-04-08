import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignatureValidation } from "./CryptoSignatureValidation";

export interface ICryptoSignatureSerialized extends ISerialized {
    sig: string;
    alg: number;
    kid?: string;
    id?: string;
}

export interface ICryptoSignature extends ISerializable {
    signature: CoreBuffer;
    algorithm: CryptoHashAlgorithm;
    keyId?: string;
    id?: string;
}

@type("CryptoSignature")
export class CryptoSignature extends CryptoSerializable implements ICryptoSignature, IClearable {
    public readonly signature: CoreBuffer;
    public readonly algorithm: CryptoHashAlgorithm;
    public readonly keyId?: string;
    public readonly id?: string;

    public constructor(signature: CoreBuffer, algorithm: CryptoHashAlgorithm, keyId?: string, id?: string) {
        let error;
        error = CryptoSignatureValidation.checkHashAlgorithm(algorithm);
        if (error) throw error;

        error = CryptoSignatureValidation.checkSignatureAsBuffer(signature);
        if (error) throw error;

        super();

        this.signature = signature;
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.id = id;
    }

    public toJSON(verbose = true): ICryptoSignatureSerialized {
        const obj: ICryptoSignatureSerialized = {
            sig: this.signature.toBase64URL(),
            alg: this.algorithm
        };
        if (verbose) {
            obj["@type"] = "CryptoSignature";
        }
        return obj;
    }

    public clear(): void {
        this.signature.clear();
    }

    public static from(value: CryptoSignature | ICryptoSignature): CryptoSignature {
        return new CryptoSignature(value.signature, value.algorithm);
    }

    public static fromJSON(value: ICryptoSignatureSerialized): CryptoSignature {
        let error = CryptoSignatureValidation.checkHashAlgorithm(value.alg);
        if (error) throw error;

        error = CryptoSignatureValidation.checkSignatureAsString(value.sig);
        if (error) throw error;

        const buffer = CoreBuffer.fromBase64URL(value.sig);
        return new CryptoSignature(buffer, value.alg as CryptoHashAlgorithm);
    }

    public static fromBase64(value: string): CryptoSignature {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static deserialize(value: string): CryptoSignature {
        const obj = JSON.parse(value);
        return this.fromJSON(obj);
    }
}
