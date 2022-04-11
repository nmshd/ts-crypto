import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoPublicKey } from "../CryptoPublicKey";
import { CryptoSignatureAlgorithm } from "./CryptoSignatureAlgorithm";
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
    @validate()
    @serialize()
    public override readonly algorithm: CryptoSignatureAlgorithm;

    @validate()
    @serialize()
    public override readonly publicKey: CoreBuffer;

    public override toJSON(verbose = true): ICryptoSignaturePublicKeySerialized {
        return {
            pub: this.publicKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoSignaturePublicKey" : undefined
        };
    }

    public clear(): void {
        this.publicKey.clear();
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public static override from(value: CryptoSignaturePublicKey | ICryptoSignaturePublicKey): CryptoSignaturePublicKey {
        return this.fromAny(value);
    }

    public static override preFrom(value: any): any {
        if (value.pub) {
            value = {
                algorithm: value.alg,
                publicKey: value.pub
            };
        }

        let error = CryptoSignatureValidation.checkSignatureAlgorithm(value.algorithm);
        if (error) throw error;

        error = CryptoSignatureValidation.checkSignaturePublicKeyAsString(
            value.publicKey,
            value.algorithm as CryptoSignatureAlgorithm,
            "publicKey"
        );
        if (error) throw error;

        return value;
    }

    public static fromJSON(value: ICryptoSignaturePublicKeySerialized): CryptoSignaturePublicKey {
        return this.fromAny(value);
    }

    public static override fromBase64(value: string): CryptoSignaturePublicKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
