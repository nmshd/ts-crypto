import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
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
    public readonly algorithm: CryptoEncryptionAlgorithm;
    public readonly receivingKey: CoreBuffer;
    public readonly transmissionKey: CoreBuffer;

    public constructor(receivingKey: CoreBuffer, transmissionKey: CoreBuffer, algorithm: CryptoEncryptionAlgorithm) {
        super();

        this.receivingKey = receivingKey;
        this.transmissionKey = transmissionKey;
        this.algorithm = algorithm;
    }

    public override toJSON(verbose = true): ICryptoExchangeSecretsSerialized {
        const obj: ICryptoExchangeSecretsSerialized = {
            rx: this.receivingKey.toBase64URL(),
            tx: this.transmissionKey.toBase64URL(),
            alg: this.algorithm
        };
        if (verbose) {
            obj["@type"] = "CryptoExchangeSecrets";
        }
        return obj;
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
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!value.algorithm || !value.receivingKey || !value.transmissionKey) {
            throw new Error("No algorithm, receivingKey or transmissionKey property set.");
        }

        const receivingKey = CoreBuffer.from(value.receivingKey);
        const transmissionKey = CoreBuffer.from(value.transmissionKey);
        return new CryptoExchangeSecrets(receivingKey, transmissionKey, value.algorithm);
    }

    public static fromJSON(value: ICryptoExchangeSecretsSerialized): CryptoExchangeSecrets {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!value.alg || !value.rx || !value.tx) {
            throw new Error("No algorithm, receivingKey or transmissionKey property set.");
        }

        const receivingKey = CoreBuffer.fromBase64URL(value.rx);
        const transmissionKey = CoreBuffer.fromBase64URL(value.tx);
        return new CryptoExchangeSecrets(receivingKey, transmissionKey, value.alg);
    }

    public static fromBase64(value: string): Promise<CryptoExchangeSecrets> {
        return Promise.resolve(this.deserialize(CoreBuffer.base64_utf8(value)));
    }
}
