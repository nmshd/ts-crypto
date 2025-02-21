import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoSerializableAsync } from "src/CryptoSerializable";
import {
    CryptoSignaturePrivateKeyHandle,
    ICryptoSignaturePrivateKeyHandle,
    ICryptoSignaturePrivateKeyHandleSerialized
} from "./CryptoSignaturePrivateKeyHandle";
import {
    CryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandleSerialized
} from "./CryptoSignaturePublicKeyHandle";

export interface ICryptoSignatureKeypairHandleSerialized extends ISerialized {
    pub: ICryptoSignaturePublicKeyHandleSerialized;
    prv: ICryptoSignaturePrivateKeyHandleSerialized;
}

export interface ICryptoSignatureKeypairHandle extends ISerializable {
    publicKey: ICryptoSignaturePublicKeyHandle;
    privateKey: ICryptoSignaturePrivateKeyHandle;
}

@type("CryptoSignatureKeypairHandle")
export class CryptoSignatureKeypairHandle extends CryptoSerializableAsync implements ICryptoSignatureKeypairHandle {
    @validate()
    @serialize()
    public publicKey: CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize()
    public privateKey: CryptoSignaturePrivateKeyHandle;

    public override toJSON(verbose = true): ICryptoSignatureKeypairHandleSerialized {
        return {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false),
            "@type": verbose ? "CryptoSignatureKeypairHandle" : undefined
        };
    }

    public static async from(
        value: CryptoSignatureKeypairHandle | ICryptoSignatureKeypairHandle
    ): Promise<CryptoSignatureKeypairHandle> {
        return await this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.pub) {
            value = {
                publicKey: value.pub,
                privateKey: value.prv
            };
        }

        if (value.privateKey.spec !== value.publicKey.spec) {
            throw new CryptoError(
                CryptoErrorCode.SignatureWrongAlgorithm,
                "Spec of private and public key handles do not match."
            );
        }

        return value;
    }

    public static async fromJSON(
        value: ICryptoSignatureKeypairHandleSerialized
    ): Promise<CryptoSignatureKeypairHandle> {
        return await this.fromAny(value);
    }

    public static async fromBase64(value: string): Promise<CryptoSignatureKeypairHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
