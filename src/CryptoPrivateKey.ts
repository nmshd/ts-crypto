import { type } from "@js-soft/ts-serval";
import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoSerializable } from "./CryptoSerializable";
import { CryptoExchangeAlgorithm } from "./exchange/CryptoExchange";
import { CryptoSignatureAlgorithm } from "./signature/CryptoSignatures";

export interface ICryptoPrivateKey {
    readonly privateKey: ICoreBuffer;
    readonly algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;
    toString(): string;
    toPEM(): string;
}

export interface ICryptoPrivateKeyStatic {
    new (): ICryptoPrivateKey;
    fromPEM(pem: string, algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm): Promise<ICryptoPrivateKey>;
    fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding
    ): Promise<ICryptoPrivateKey>;
    fromNativeKey(key: any, algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm): Promise<ICryptoPrivateKey>;
}

@type("CryptoPrivateKey")
export class CryptoPrivateKey extends CryptoSerializable implements ICryptoPrivateKey {
    public readonly algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;
    public readonly privateKey: ICoreBuffer;

    public constructor(algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm, privateKey: ICoreBuffer) {
        super();

        this.algorithm = algorithm;
        this.privateKey = privateKey;
    }

    public toJSON(): Object {
        const obj = {
            "@type": "CryptoPrivateKey",
            privateKey: this.toString(),
            algorithm: this.algorithm
        };
        return obj;
    }

    public toString(): string {
        return this.privateKey.toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    public toPEM(): string {
        return this.privateKey.toString(Encoding.Pem, "PRIVATE KEY");
    }

    protected static stripPEM(pem: string): string {
        pem = pem.replace(/-----BEGIN [\w ]* KEY-----/, "");
        pem = pem.replace(/-----END [\w ]* KEY-----/, "");
        pem = pem.replace(/----- BEGIN [\w ]* KEY -----/, "");
        pem = pem.replace(/----- END [\w ]* KEY -----/, "");
        pem = pem.replace(/(?:\r\n|\r|\n)/g, "");
        return pem;
    }

    public static deserialize(value: string): CryptoPrivateKey {
        const obj = JSON.parse(value);
        return this.from(obj);
    }

    public static fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding = Encoding.Base64_UrlSafe_NoPadding
    ): CryptoPrivateKey {
        const buffer: CoreBuffer = CoreBuffer.fromString(value, encoding);

        return new CryptoPrivateKey(algorithm, buffer);
    }

    public static fromObject(
        value: any,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): CryptoPrivateKey {
        const buffer: ICoreBuffer = CoreBuffer.fromObject(value);

        return new CryptoPrivateKey(algorithm, buffer);
    }

    public static fromPEM(
        pem: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): CryptoPrivateKey {
        const value = this.stripPEM(pem);
        return this.fromString(value, algorithm, Encoding.Base64);
    }

    public static from(value: any): CryptoPrivateKey {
        if (!value || !value.publicKey || !value.algorithm) {
            throw new Error("No value, public key or algorithm set");
        }

        if (typeof value.privateKey === "string") {
            return this.fromString(value.privateKey, value.algorithm);
        }
        return this.fromObject(value.privateKey, value.algorithm);
    }

    public static fromBase64(value: string): CryptoPrivateKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
