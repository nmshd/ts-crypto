import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { Provider } from "crypto-layer-ts-types";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoLayerKeyPair } from "src/CryptoLayerKeyPair";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoPrivateKey } from "../CryptoPrivateKey";
import { CryptoSignatureAlgorithm } from "./CryptoSignatureAlgorithm";
import { CryptoSignaturePublicKey } from "./CryptoSignaturePublicKey";
import { CryptoSignatures } from "./CryptoSignatures";
import { CryptoSignatureValidation } from "./CryptoSignatureValidation";

export interface ICryptoSignaturePrivateKeySerialized extends ISerialized {
    alg: number; // algorithm
    prv?: string; // privateKey
    id?: string;
    kid?: string; // keyId
    pnm?: string; // providerName
}
export interface ICryptoSignaturePrivateKey extends ISerializable {
    algorithm: CryptoSignatureAlgorithm;
    privateKey: ICoreBuffer | CryptoLayerKeyPair;
    id?: string;
}

@type("CryptoSignaturePrivateKey")
export class CryptoSignaturePrivateKey extends CryptoPrivateKey implements ICryptoSignaturePrivateKey, IClearable {
    public override algorithm: CryptoSignatureAlgorithm;

    @validate({ nullable: true })
    @serialize()
    public id?: string;

    public override toJSON(verbose = true): ICryptoSignaturePrivateKeySerialized {
        if (this.privateKey instanceof CoreBuffer) {
            return {
                prv: this.privateKey.toBase64URL(),
                alg: this.algorithm,
                id: this.id,
                "@type": verbose ? "CryptoSignaturePrivateKey" : undefined
            };
        }

        if (!this.privateKey.keyPairHandle || !this.privateKey.provider) {
            throw new CryptoError(
                CryptoErrorCode.CalUninitializedKey,
                "The key pair does not hold a key pair handle. It needs to be loaded from a provider via the init method."
            );
        }
        return {
            alg: this.algorithm,
            kid: this.privateKey.keyPairHandle.id(),
            pnm: this.privateKey.provider.providerName()
        };
    }

    public clear(): void {
        if (this.privateKey instanceof CoreBuffer) {
            this.privateKey.clear();
        }
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Returns the public key of this private key.
     *
     * @param provider If defined, will create the public key with this provider instead of the provider used by the private key.
     * @returns CryptoSignaturePublicKey
     *
     * @throws `CryptoErrorCode.CalUninitializedKey` - If `privateKey` is an uninitialized crypto layer key pair handle.
     */
    public async toPublicKey(provider?: Provider): Promise<CryptoSignaturePublicKey> {
        if (this.privateKey instanceof CoreBuffer) {
            return await CryptoSignatures.privateKeyToPublicKey(this);
        }

        provider = provider ?? this.privateKey.provider;
        if (!this.privateKey.keyPairHandle || !provider) {
            throw new CryptoError(
                CryptoErrorCode.CalUninitializedKey,
                "The key pair does not hold a key pair handle. It needs to be loaded from a provider via the init method."
            );
        }

        let rawPublicKey = new CoreBuffer(this.privateKey.keyPairHandle.getPublicKey());
        let spec = this.privateKey.keyPairHandle.spec();
        let newKeyPair = provider.importPublicKey(spec, rawPublicKey.buffer);
        rawPublicKey.clear();
        let cryptoLayerKeyPair = new CryptoLayerKeyPair(provider, newKeyPair);
        return CryptoSignaturePublicKey.fromAny({ algorithm: this.algorithm, publicKey: rawPublicKey });
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
                privateKey: value.prv,
                id: value.id
            };
        } else if (value.kid && value.pnm) {
            let keyPairHandle = CryptoLayerKeyPair.fromAny({ id: value.kid, providerName: value.pnm });
            value = {
                algorithm: value.alg,
                privateKey: keyPairHandle,
                id: value.id
            };
        }

        CryptoSignatureValidation.checkSignatureAlgorithm(value.algorithm);

        if (value.privateKey instanceof CoreBuffer) {
            CryptoSignatureValidation.checkSignaturePrivateKey(value.privateKey, "privateKey");
        }

        return value;
    }

    public static fromJSON(value: ICryptoSignaturePrivateKeySerialized): CryptoSignaturePrivateKey {
        return this.fromAny(value);
    }

    public static override fromBase64(value: string): CryptoSignaturePrivateKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
