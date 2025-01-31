import { serialize, type, validate } from "@js-soft/ts-serval";
import { Provider } from "crypto-layer-ts-types";
import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { CryptoLayerKeyPair } from "./CryptoLayerKeyPair";
import { CryptoSerializable } from "./CryptoSerializable";
import { CryptoExchangeAlgorithm } from "./exchange/CryptoExchange";
import { CryptoSignatureAlgorithm } from "./signature/CryptoSignatureAlgorithm";

export interface ICryptoPublicKey {
    publicKey: ICoreBuffer | CryptoLayerKeyPair;
    algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;
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
    @validate()
    @serialize()
    public algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm;

    @validate()
    @serialize()
    public publicKey: CoreBuffer | CryptoLayerKeyPair;

    public override toString(): string {
        if (this.publicKey instanceof CoreBuffer) {
            return this.publicKey.toString(Encoding.Base64_UrlSafe_NoPadding);
        }

        if (!this.publicKey.keyPairHandle) {
            throw new CryptoError(
                CryptoErrorCode.CalUninitializedKey,
                "The key pair does not hold a key pair handle. It needs to be loaded from a provider via the init method."
            );
        }
        let privateRawKey = this.publicKey.keyPairHandle.extractKey();
        return new CoreBuffer(privateRawKey).toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    public toPEM(): string {
        if (this.publicKey instanceof CoreBuffer) {
            return this.publicKey.toString(Encoding.Pem, "PUBLIC KEY");
        }

        if (!this.publicKey.keyPairHandle) {
            throw new CryptoError(
                CryptoErrorCode.CalUninitializedKey,
                "The key pair does not hold a key pair handle. It needs to be loaded from a provider via the init method."
            );
        }
        let privateRawKey = this.publicKey.keyPairHandle.extractKey();
        return new CoreBuffer(privateRawKey).toString(Encoding.Pem, "PUBLIC KEY");
    }

    protected static stripPEM(pem: string): string {
        pem = pem.replace(/-----BEGIN [\w ]* KEY-----/, "");
        pem = pem.replace(/-----END [\w ]* KEY-----/, "");
        pem = pem.replace(/----- BEGIN [\w ]* KEY -----/, "");
        pem = pem.replace(/----- END [\w ]* KEY -----/, "");
        pem = pem.replace(/(?:\r\n|\r|\n)/g, "");
        return pem;
    }

    public static fromPEM(
        pem: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        provider?: Provider
    ): CryptoPublicKey {
        const value = this.stripPEM(pem);
        return this.fromString(value, algorithm, Encoding.Base64, provider);
    }

    public static fromString(
        value: string,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        encoding: Encoding = Encoding.Base64_UrlSafe_NoPadding,
        provider?: Provider
    ): CryptoPublicKey {
        const buffer = CoreBuffer.fromString(value, encoding);
        if (!provider) {
            return this.fromAny({ algorithm, publicKey: buffer });
        }
        return this.fromAny({
            algorithm,
            privateKey: CryptoLayerKeyPair.fromPublicBufferWithAlgorithm(provider, buffer, algorithm)
        });
    }

    public static fromObject(
        value: any,
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        provider?: Provider
    ): CryptoPublicKey {
        const buffer = CoreBuffer.fromObject(value);
        if (!provider) {
            return this.fromAny({ algorithm, publicKey: buffer });
        }
        return this.fromAny({
            algorithm,
            privateKey: CryptoLayerKeyPair.fromPublicBufferWithAlgorithm(provider, buffer, algorithm)
        });
    }

    public static from(value: any): CryptoPublicKey {
        return this.fromAny(value);
    }

    public static fromBase64(value: string, provider?: Provider): CryptoPublicKey {
        let publicKey = this.deserialize(CoreBuffer.base64_utf8(value));
        if (provider && publicKey.publicKey instanceof CryptoLayerKeyPair) {
            publicKey.publicKey.init(provider);
        }
        return publicKey;
    }
}
