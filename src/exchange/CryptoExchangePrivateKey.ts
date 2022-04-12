import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoPrivateKey } from "../CryptoPrivateKey";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoExchangeAlgorithm } from "./CryptoExchange";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeValidation } from "./CryptoExchangeValidation";

export interface ICryptoExchangePrivateKeySerialized extends ISerialized {
    alg: number;
    prv: string;
}

export interface ICryptoExchangePrivateKey extends ISerializable {
    algorithm: CryptoExchangeAlgorithm;
    privateKey: ICoreBuffer;
}

@type("CryptoExchangePrivateKey")
export class CryptoExchangePrivateKey extends CryptoPrivateKey implements ICryptoExchangePrivateKey, IClearable {
    @validate()
    @serialize()
    public override algorithm: CryptoExchangeAlgorithm;

    @validate()
    @serialize()
    public override privateKey: CoreBuffer;

    public override toJSON(verbose = true): ICryptoExchangePrivateKeySerialized {
        return {
            prv: this.privateKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangePrivateKey" : undefined
        };
    }

    public clear(): void {
        this.privateKey.clear();
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public async toPublicKey(): Promise<CryptoExchangePublicKey> {
        let publicKey: Uint8Array;
        switch (this.algorithm) {
            case CryptoExchangeAlgorithm.ECDH_X25519:
                try {
                    publicKey = (await SodiumWrapper.ready()).crypto_scalarmult_base(this.privateKey.buffer);
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.ExchangeKeyGeneration, `${e}`);
                }
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }

        return CryptoExchangePublicKey.from({
            algorithm: this.algorithm,
            publicKey: CoreBuffer.from(publicKey)
        });
    }

    public static override from(value: CryptoExchangePrivateKey | ICryptoExchangePrivateKey): CryptoExchangePrivateKey {
        return this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.alg) {
            value = {
                algorithm: value.alg,
                privateKey: CoreBuffer.fromBase64URL(value.prv)
            };
        }

        CryptoExchangeValidation.checkExchangeAlgorithm(value.algorithm);
        CryptoExchangeValidation.checkExchangePrivateKey(value.privateKey, value.algorithm, "privateKey");

        return value;
    }

    public static fromJSON(value: ICryptoExchangePrivateKeySerialized): CryptoExchangePrivateKey {
        return this.fromAny(value);
    }

    public static override fromBase64(value: string): CryptoExchangePrivateKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
