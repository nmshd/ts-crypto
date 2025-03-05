import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoPublicKeyHandle } from "../CryptoPublicKeyHandle";

export interface ICryptoSignaturePublicKeyHandleSerialized extends ISerialized {
    spc: KeyPairSpec; // Specification/Config of key pair stored.
    cid: string; // Crypto layer key pair id used for loading key from a provider.
    pnm: string; // Provider name
    pub?: string; // Raw public key. If not undefined tries to import this key.
}
export interface ICryptoSignaturePublicKeyHandle extends ISerializable {
    spec: KeyPairSpec;
    id: string;
    providerName: string;
    rawPublicKey?: CoreBuffer;
}

@type("CryptoSignaturePublicKeyHandle")
export class CryptoSignaturePublicKeyHandle extends CryptoPublicKeyHandle {
    public override toJSON(verbose = true): ICryptoSignaturePublicKeyHandleSerialized {
        return {
            spc: this.spec,
            cid: this.id,
            pnm: this.providerName,
            pub: this.rawPublicKey?.toBase64URL(),
            "@type": verbose ? "CryptoSignaturePublicKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    public static override async from(
        value: CryptoSignaturePublicKeyHandle | ICryptoSignaturePublicKeyHandle
    ): Promise<CryptoSignaturePublicKeyHandle> {
        return await this.fromAny(value);
    }

    public static override preFrom(value: any): any {
        if (value.cid) {
            value = {
                spec: value.spc,
                id: value.cid,
                providerName: value.pnm,
                rawPublicKey: value.pub
            };
        }

        return value;
    }

    public static async fromJSON(
        value: ICryptoSignaturePublicKeyHandleSerialized
    ): Promise<CryptoSignaturePublicKeyHandle> {
        return await this.fromAny(value);
    }

    public static override async fromBase64(value: string): Promise<CryptoSignaturePublicKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
