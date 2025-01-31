import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoLayerKeyPair } from "src/CryptoLayerKeyPair";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoPublicKey } from "../CryptoPublicKey";
import { CryptoSignatureAlgorithm } from "./CryptoSignatureAlgorithm";
import { CryptoSignatureValidation } from "./CryptoSignatureValidation";

export interface ICryptoSignaturePublicKeySerialized extends ISerialized {
    alg: number; // algorithm
    pub?: string; // publicKey
    kid?: string; // keyId
    pnm?: string; // providerName
}

export interface ICryptoSignaturePublicKey extends ISerializable {
    algorithm: CryptoSignatureAlgorithm;
    publicKey: ICoreBuffer | CryptoLayerKeyPair;
}

@type("CryptoSignaturePublicKey")
export class CryptoSignaturePublicKey extends CryptoPublicKey implements ICryptoSignaturePublicKey, IClearable {
    public override algorithm: CryptoSignatureAlgorithm;

    public override toJSON(verbose = true): ICryptoSignaturePublicKeySerialized {
        if (this.publicKey instanceof CoreBuffer) {
            return {
                alg: this.algorithm,
                pub: this.publicKey.toBase64URL(),
                "@type": verbose ? "CryptoSignaturePublicKey" : undefined
            };
        }

        if (!this.publicKey.keyPairHandle || !this.publicKey.provider) {
            throw new CryptoError(
                CryptoErrorCode.CalUninitializedKey,
                "The key pair does not hold a key pair handle. It needs to be loaded from a provider via the init method."
            );
        }
        return {
            alg: this.algorithm,
            kid: this.publicKey.keyPairHandle.id(),
            pnm: this.publicKey.provider.providerName()
        };
    }

    public clear(): void {
        if (this.publicKey instanceof CoreBuffer) {
            this.publicKey.clear();
        }
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
        } else if (value.kid && value.pnm) {
            let keyPairHandle = CryptoLayerKeyPair.fromAny({ id: value.kid, providerName: value.pnm });
            value = {
                algorithm: value.alg,
                publicKey: keyPairHandle
            };
        }

        CryptoSignatureValidation.checkSignatureAlgorithm(value.algorithm);

        if (value.publicKey instanceof CoreBuffer) {
            CryptoSignatureValidation.checkSignaturePublicKey(value.publicKey, value.algorithm, "publicKey");
        }

        return value;
    }

    public static fromJSON(value: ICryptoSignaturePublicKeySerialized): CryptoSignaturePublicKey {
        return this.fromAny(value);
    }

    public static override fromBase64(value: string): CryptoSignaturePublicKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
