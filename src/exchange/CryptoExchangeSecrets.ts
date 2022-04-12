import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";

export interface ICryptoExchangeSecretsSerialized extends ISerialized {
    alg: CryptoEncryptionAlgorithm;
    rx: string;
    tx: string;
}

export interface ICryptoExchangeSecrets extends ISerializable {
    algorithm: CryptoEncryptionAlgorithm;
    receivingKey: ICoreBuffer;
    transmissionKey: ICoreBuffer;
}

@type("CryptoExchangeSecrets")
export class CryptoExchangeSecrets extends CryptoSerializable implements ICryptoExchangeSecrets, IClearable {
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public receivingKey: CoreBuffer;

    @validate()
    @serialize()
    public transmissionKey: CoreBuffer;

    public override toJSON(verbose = true): ICryptoExchangeSecretsSerialized {
        return {
            rx: this.receivingKey.toBase64URL(),
            tx: this.transmissionKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangeSecrets" : undefined
        };
    }

    public clear(): void {
        this.receivingKey.clear();
        this.transmissionKey.clear();
    }

    public override serialize(verbose = true): string {
        return JSON.stringify(this.toJSON(verbose));
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public static from(value: CryptoExchangeSecrets | ICryptoExchangeSecrets): CryptoExchangeSecrets {
        return this.fromAny(value);
    }

    public static override preFrom(value: any): any {
        if (value.rx) {
            value = {
                algorithm: value.alg,
                receivingKey: value.rx,
                transmissionKey: value.tx
            };
        }
        return value;
    }

    public static fromJSON(value: ICryptoExchangeSecretsSerialized): CryptoExchangeSecrets {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): Promise<CryptoExchangeSecrets> {
        return Promise.resolve(this.deserialize(CoreBuffer.base64_utf8(value)));
    }
}
