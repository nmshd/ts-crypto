import { type } from "@js-soft/ts-serval";
import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoSerializable } from "./CryptoSerializable";
import { CryptoExchangeAlgorithm } from "./exchange/CryptoExchange";
import { CryptoSignatureAlgorithm } from "./signature/CryptoSignatures";

export interface ICryptoPublicKey {
    readonly publicKey: ICoreBuffer;
    readonly algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;
    toString(): string;
    toPEM(): string;
    toJSON(): Object;
}

export interface ICryptoPublicKeyStatic {
    new (): ICryptoPublicKey;
    fromPEM(pem: string, algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm): Promise<CryptoPublicKey>;
    fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding
    ): Promise<CryptoPublicKey>;
    fromNativeKey(key: any, algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm): Promise<CryptoPublicKey>;
}

@type("CryptoPublicKey")
export class CryptoPublicKey extends CryptoSerializable implements ICryptoPublicKey {
    public readonly algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;
    public readonly publicKey: ICoreBuffer;

    public constructor(algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm, publicKey: ICoreBuffer) {
        super();
        this.algorithm = algorithm;
        this.publicKey = publicKey;
    }

    public toJSON(): Object {
        const obj = {
            "@type": "CryptoPublicKey",
            publicKey: this.toString(),
            algorithm: this.algorithm
        };
        return obj;
    }

    public toString(): string {
        return this.publicKey.toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    public toPEM(): string {
        return this.publicKey.toString(Encoding.Pem, "PUBLIC KEY");
    }

    protected static stripPEM(pem: string): string {
        pem = pem.replace(/-----BEGIN [\w ]* KEY-----/, "");
        pem = pem.replace(/-----END [\w ]* KEY-----/, "");
        pem = pem.replace(/----- BEGIN [\w ]* KEY -----/, "");
        pem = pem.replace(/----- END [\w ]* KEY -----/, "");
        pem = pem.replace(/(?:\r\n|\r|\n)/g, "");
        return pem;
    }

    public static fromPEM(pem: string, algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm): CryptoPublicKey {
        const value = this.stripPEM(pem);
        return this.fromString(value, algorithm, Encoding.Base64);
    }

    public static fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding = Encoding.Base64_UrlSafe_NoPadding
    ): CryptoPublicKey {
        const buffer: ICoreBuffer = CoreBuffer.fromString(value, encoding);

        return new CryptoPublicKey(algorithm, buffer);
    }

    public static fromObject(
        value: any,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): CryptoPublicKey {
        const buffer = CoreBuffer.fromObject(value);

        return new CryptoPublicKey(algorithm, buffer);
    }

    public static deserialize(value: string): CryptoPublicKey {
        const obj = JSON.parse(value);
        return this.from(obj);
    }

    public static from(value: any): CryptoPublicKey {
        if (!value || !value.publicKey || !value.algorithm) {
            throw new Error("No value, public key or algorithm set");
        }

        if (typeof value.privateKey === "string") {
            return this.fromString(value.publicKey, value.algorithm);
        }
        return this.fromObject(value.publicKey, value.algorithm);
    }

    public static fromBase64(value: string): CryptoPublicKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
