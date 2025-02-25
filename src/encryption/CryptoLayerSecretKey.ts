import { ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyHandle } from "crypto-layer-ts-types";
import { getProvider } from "src/CryptoLayerProviders";
import { CryptoSerializableAsync } from "src/CryptoSerializable";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm, CryptoEncryptionAlgorithmUtil } from "./CryptoEncryption";

interface ICryptoLayerSecretKeySerialized extends ISerialized {
    algorithm: number;
    id: string;
    providername: string;
}

@type("CryptoLayerSecretKey")
export class CryptoLayerSecretKey extends CryptoSerializableAsync {
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;
    
    @validate()
    @serialize()
    public id: string;

    @validate()
    @serialize()
    public providername: string;

    keyHandle: KeyHandle;

    public static async getFromHandle(providername: string, id: string) {
        // load keyHandle from the id
        const provider = getProvider(providername);

        const key = await provider.loadKey(id);
        const alg = CryptoEncryptionAlgorithmUtil.fromCalCipher((await key.spec()).cipher)
        return this.fromAny({algorithm: alg, id, providername});
    }

    public constructor(algorithm: CryptoEncryptionAlgorithm, id: string, providername: string) {
        super();

        this.algorithm = algorithm;
        this.id = id;
        this.providername = providername;
    }

    public override toJSON(verbose = true): ICryptoLayerSecretKeySerialized {
        return {
            id: this.id,
            algorithm: this.algorithm,
            providername: this.providername,
            "@type": verbose ? "CryptoLayerSecretKey" : "CryptoLayerSecretKey"
        };
    }

    protected static override async postFrom(value: any): Promise<any> {

        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);

        // load keyHandle from the id
        const provider = getProvider(value.providername);

        const key = await provider.loadKey(value.id);

        value.keyHandle = key;
        return value;
    }

    public static fromJSON(value: ICryptoLayerSecretKeySerialized): Promise<CryptoLayerSecretKey> {
        return this.fromAny(value);
    }
}
