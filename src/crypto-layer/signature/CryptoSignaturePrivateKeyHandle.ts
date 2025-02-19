import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoPrivateKeyHandle } from "../CryptoPrivateKeyHandle";

export interface ICryptoSignaturePrivateKeyHandleSerialized extends ISerialized {
    spc: KeyPairSpec; // Specification/Config of key pair stored.
    cid: string; // Crypto layer key pair id used for loading key from a provider.
    pnm: string; // Provider name
}
export interface ICryptoSignaturePrivateKeyHandle extends ISerializable {
    spec: KeyPairSpec;
    id: string;
    providerName: string;
}

@type("CryptoSignaturePrivateKeyHandle")
export class CryptoSignaturePrivateKeyHandle extends CryptoPrivateKeyHandle {
    public override toJSON(verbose = true): ICryptoSignaturePrivateKeyHandleSerialized {
        return {
            spc: this.spec,
            cid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "CryptoSignaturePrivateKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public static override async from(
        value: CryptoSignaturePrivateKeyHandle | ICryptoSignaturePrivateKeyHandle
    ): Promise<CryptoSignaturePrivateKeyHandle> {
        return await this.fromAny(value);
    }

    public static override preFrom(value: any): any {
        if (value.cid) {
            value = {
                spec: value.spc,
                id: value.cid,
                providerName: value.pnm
            };
        }

        return value;
    }

    public static async fromJSON(
        value: ICryptoSignaturePrivateKeyHandleSerialized
    ): Promise<CryptoSignaturePrivateKeyHandle> {
        return await this.fromAny(value);
    }

    public static override async fromBase64(value: string): Promise<CryptoSignaturePrivateKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
