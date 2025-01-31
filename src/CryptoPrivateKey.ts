import { serialize, type, validate } from "@js-soft/ts-serval";
import { Provider } from "crypto-layer-ts-types";
import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { CryptoLayerKeyPair } from "./CryptoLayerKeyPair";
import { CryptoSerializable } from "./CryptoSerializable";
import { CryptoExchangeAlgorithm } from "./exchange/CryptoExchange";
import { CryptoSignatureAlgorithm } from "./signature/CryptoSignatureAlgorithm";

export interface ICryptoPrivateKey {
    privateKey: ICoreBuffer | CryptoLayerKeyPair;
    algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;
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
    @validate()
    @serialize()
    public algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;

    @validate()
    @serialize()
    public privateKey: CoreBuffer | CryptoLayerKeyPair;

    public toPEM(): string {
        if (this.privateKey instanceof CoreBuffer) {
            return this.privateKey.toString(Encoding.Pem, "PRIVATE KEY");
        } else {
            throw new CryptoError(
                CryptoErrorCode.NotYetImplemented,
                "Extraction is in the trait but not the structs implementation."
            );
        }
    }

    public override toString(): string {
        if (this.privateKey instanceof CoreBuffer) {
            return this.privateKey.toString(Encoding.Base64_UrlSafe_NoPadding);
        } else {
            throw new CryptoError(
                CryptoErrorCode.NotYetImplemented,
                "Extraction is in the trait but not the structs implementation."
            );
        }
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
        encoding: Encoding = Encoding.Base64_UrlSafe_NoPadding,
        provider?: Provider
    ): CryptoPrivateKey {
        const buffer: CoreBuffer = CoreBuffer.fromString(value, encoding);
        if (!provider) {
            return this.fromAny({ algorithm, privateKey: buffer });
        }
        return this.fromAny({
            algorithm,
            privateKey: CryptoLayerKeyPair.fromPrivateBufferWithAlgorithm(provider, buffer, algorithm)
        });
    }

    public static fromObject(
        value: any,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        provider?: Provider
    ): CryptoPrivateKey {
        const buffer: CoreBuffer = CoreBuffer.fromObject(value);
        if (!provider) {
            return this.fromAny({ algorithm, privateKey: buffer });
        }
        return this.fromAny({
            algorithm,
            privateKey: CryptoLayerKeyPair.fromPrivateBufferWithAlgorithm(provider, buffer, algorithm)
        });
    }

    public static fromPEM(
        pem: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        provider?: Provider
    ): CryptoPrivateKey {
        const value = this.stripPEM(pem);
        return this.fromString(value, algorithm, Encoding.Base64, provider);
    }

    public static from(value: any): CryptoPrivateKey {
        return this.fromAny(value);
    }

    public static fromBase64(value: string, provider?: Provider): CryptoPrivateKey {
        let privateKey = this.deserialize(CoreBuffer.base64_utf8(value));
        if (provider && privateKey.privateKey instanceof CryptoLayerKeyPair) {
            privateKey.privateKey.init(provider);
        }
        return privateKey;
    }
}
