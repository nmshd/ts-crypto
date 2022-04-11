import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
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
export interface ICryptoSignaturePrivateKey extends ISerializable {
    algorithm: CryptoSignatureAlgorithm;
    privateKey: ICoreBuffer;
    id?: string;
}

@type("CryptoSignaturePrivateKey")
export class CryptoSignaturePrivateKey extends CryptoPrivateKey implements ICryptoSignaturePrivateKey, IClearable {
    public override readonly algorithm: CryptoSignatureAlgorithm;
    public override readonly privateKey: CoreBuffer;
    public readonly id?: string;

    public override toJSON(verbose = true): ICryptoSignaturePrivateKeySerialized {
        return {
            prv: this.privateKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoSignaturePrivateKey" : undefined
        };
    }

    public clear(): void {
        this.privateKey.clear();
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public async toPublicKey(): Promise<CryptoSignaturePublicKey> {
        return await CryptoSignatures.privateKeyToPublicKey(this);
    }

    public static override from(
        value: CryptoSignaturePrivateKey | ICryptoSignaturePrivateKey
    ): CryptoSignaturePrivateKey {
        return this.fromAny(value);
    }

    public static override preFrom(value: any): any {
        if (value.prv) {
            value = {
                algorithm: value.alg,
                privateKey: value.prv
            };
        }

        let error = CryptoSignatureValidation.checkSignatureAlgorithm(value.algorithm);
        if (error) throw error;

        error = CryptoSignatureValidation.checkSignaturePrivateKeyAsString(value.privateKey, "privateKey");
        if (error) throw error;

        return value;
    }

    public static fromJSON(value: ICryptoSignaturePrivateKeySerialized): CryptoSignaturePrivateKey {
        return this.fromAny(value);
    }

    public static override fromBase64(value: string): CryptoSignaturePrivateKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
