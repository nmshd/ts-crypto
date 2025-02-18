import { serialize, type, validate } from "@js-soft/ts-serval";
import { Provider, SecurityLevel } from "@nmshd/rs-crypto-types";
import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { CryptoLayerKeyPair } from "./CryptoLayerKeyPair";
import { getProvider } from "./CryptoLayerProviders";
import { CryptoSerializable } from "./CryptoSerializable";
import { CryptoExchangeAlgorithm } from "./exchange/CryptoExchange";
import { CryptoHashAlgorithm } from "./hash/CryptoHash";
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
        }

        if (!this.privateKey.keyPairHandle) {
            throw new CryptoError(
                CryptoErrorCode.CalUninitializedKey,
                "The key pair does not hold a key pair handle. It needs to be loaded from a provider via the init method."
            );
        }
        let privateRawKey = this.privateKey.keyPairHandle.extractKey();
        return new CoreBuffer(privateRawKey).toString(Encoding.Pem, "PRIVATE KEY");
    }

    public override toString(): string {
        if (this.privateKey instanceof CoreBuffer) {
            return this.privateKey.toString(Encoding.Base64_UrlSafe_NoPadding);
        }

        if (!this.privateKey.keyPairHandle) {
            throw new CryptoError(
                CryptoErrorCode.CalUninitializedKey,
                "The key pair does not hold a key pair handle. It needs to be loaded from a provider via the init method."
            );
        }
        let privateRawKey = this.privateKey.keyPairHandle.extractKey();
        return new CoreBuffer(privateRawKey).toString(Encoding.Base64_UrlSafe_NoPadding);
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
        provider: string | SecurityLevel | undefined = "Software",
        hashAlgorithm?: CryptoHashAlgorithm
    ): CryptoPrivateKey {
        const buffer: CoreBuffer = CoreBuffer.fromString(value, encoding);
        let providerInitalized = getProvider(provider);
        if (!providerInitalized) {
            return this.fromAny({ algorithm, privateKey: buffer });
        }

        // provider load from global with config

        return this.fromAny({
            algorithm,
            privateKey: CryptoLayerKeyPair.fromPrivateBufferWithAlgorithm(
                providerInitalized,
                buffer,
                algorithm,
                hashAlgorithm
            )
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
