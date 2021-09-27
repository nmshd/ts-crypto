import { type } from "@js-soft/ts-serval";
import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoSerializableAsync } from "./CryptoSerializableAsync";
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
export class CryptoPrivateKey extends CryptoSerializableAsync implements ICryptoPrivateKey {
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

    public static async deserialize(value: string): Promise<CryptoPrivateKey> {
        const obj = JSON.parse(value);
        return await this.from(obj);
    }

    public static fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding = Encoding.Base64_UrlSafe_NoPadding
    ): Promise<CryptoPrivateKey> {
        const buffer: CoreBuffer = CoreBuffer.fromString(value, encoding);

        return Promise.resolve(new CryptoPrivateKey(algorithm, buffer));
    }

    public static fromObject(
        value: any,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): Promise<CryptoPrivateKey> {
        const buffer: ICoreBuffer = CoreBuffer.fromObject(value);

        return Promise.resolve(new CryptoPrivateKey(algorithm, buffer));
    }

    public static async fromPEM(
        pem: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): Promise<CryptoPrivateKey> {
        const value = this.stripPEM(pem);
        return await this.fromString(value, algorithm, Encoding.Base64);
    }

    public static async from(value: any): Promise<CryptoPrivateKey> {
        if (!value || !value.publicKey || !value.algorithm) {
            throw new Error("No value, public key or algorithm set");
        }

        if (typeof value.privateKey === "string") {
            return await this.fromString(value.privateKey, value.algorithm);
        }
        return await this.fromObject(value.privateKey, value.algorithm);
    }

    public static async fromBase64(value: string): Promise<CryptoPrivateKey> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
