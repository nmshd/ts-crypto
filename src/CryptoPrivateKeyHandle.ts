import { serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoSerializable } from "./CryptoSerializable";
import { CryptoExchangeAlgorithm } from "./exchange/CryptoExchange";
import { CryptoSignatureAlgorithm } from "./signature/CryptoSignatureAlgorithm";

export interface ICryptoPrivateKeyHandle {
    privateKey: ICoreBuffer;
    algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;
    toString(): string;
    toPEM(): string;
}

export interface ICryptoPrivateKeyHandleStatic {
    new (): ICryptoPrivateKeyHandle;
    fromPEM(
        pem: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): Promise<ICryptoPrivateKeyHandle>;
    fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding
    ): Promise<ICryptoPrivateKeyHandle>;
    fromNativeKey(
        key: any,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): Promise<ICryptoPrivateKeyHandle>;
}

@type("CryptoPrivateKeyHandle")
export class CryptoPrivateKeyHandle extends CryptoSerializable implements ICryptoPrivateKeyHandle {
    @validate()
    @serialize()
    public algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;

    @validate()
    @serialize()
    public privateKey: CoreBuffer;

    public toPEM(): string {
        return this.privateKey.toString(Encoding.Pem, "PRIVATE KEY");
    }

    public override toString(): string {
        return this.privateKey.toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    protected static stripPEM(pem: string): string {
        pem = pem.replace(/-----BEGIN [\w ]* KEY-----/, "");
        pem = pem.replace(/-----END [\w ]* KEY-----/, "");
        pem = pem.replace(/----- BEGIN [\w ]* KEY -----/, "");
        pem = pem.replace(/----- END [\w ]* KEY -----/, "");
        pem = pem.replace(/(?:\r\n|\r|\n)/g, "");
        return pem;
    }

    public static fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding = Encoding.Base64_UrlSafe_NoPadding
    ): CryptoPrivateKeyHandle {
        const buffer: CoreBuffer = CoreBuffer.fromString(value, encoding);
        return this.fromAny({ algorithm, privateKey: buffer });
    }

    public static fromObject(
        value: any,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): CryptoPrivateKeyHandle {
        const buffer: ICoreBuffer = CoreBuffer.fromObject(value);

        return this.fromAny({ algorithm, privateKey: buffer });
    }

    public static fromPEM(
        pem: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): CryptoPrivateKeyHandle {
        const value = this.stripPEM(pem);
        return this.fromString(value, algorithm, Encoding.Base64);
    }

    public static from(value: any): CryptoPrivateKeyHandle {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoPrivateKeyHandle {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
