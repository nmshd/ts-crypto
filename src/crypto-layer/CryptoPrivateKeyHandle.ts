import { type } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, Encoding } from "../CoreBuffer";
import { CryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";

export interface ICryptoPrivateKeyHandle {
    keyPairHandle: KeyPairHandle;
    spec: KeyPairSpec;
    toSerializedString(): Promise<string>;
    toPEM(): Promise<string>;
}

export interface ICryptoPrivateKeyHandleStatic {
    new (): ICryptoPrivateKeyHandle;
    fromPEM(providerIdent: ProviderIdentifier, pem: string, spec: KeyPairSpec): Promise<ICryptoPrivateKeyHandle>;
    fromString(
        providerIdent: ProviderIdentifier,
        value: string,
        spec: KeyPairSpec,
        encoding: Encoding
    ): Promise<ICryptoPrivateKeyHandle>;
    // fromNativeKey(providerIdent: ProviderIdentifier, key: any, config: KeyPairSpec): Promise<ICryptoPrivateKeyHandle>;
}

@type("CryptoPrivateKeyHandle")
export class CryptoPrivateKeyHandle extends CryptoAsymmetricKeyHandle implements ICryptoPrivateKeyHandle {
    public async toSerializedString(): Promise<string> {
        const raw = await this.keyPairHandle.extractKey();
        return CoreBuffer.from(raw).toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    public async toPEM(): Promise<string> {
        const raw = await this.keyPairHandle.extractKey();
        return CoreBuffer.from(raw).toString(Encoding.Pem, "PRIVATE KEY");
    }

    public static async fromString(
        providerIdent: ProviderIdentifier,
        value: string,
        spec: KeyPairSpec,
        encoding: Encoding
    ): Promise<CryptoPrivateKeyHandle> {
        const raw = CoreBuffer.fromString(value, encoding).buffer;
        const provider = getProviderOrThrow(providerIdent);
        const keyPairHandle = await provider.importKeyPair(spec, new Uint8Array(0), raw);
        return await CryptoPrivateKeyHandle.newFromProviderAndKeyPairHandle(provider, keyPairHandle, {
            keySpec: spec
        });
    }

    public static async fromPEM(
        providerIdent: ProviderIdentifier,
        pem: string,
        spec: KeyPairSpec
    ): Promise<CryptoPrivateKeyHandle> {
        return await CryptoPrivateKeyHandle.fromString(providerIdent, pem, spec, Encoding.Pem);
    }
}

const _testAssign: ICryptoPrivateKeyHandleStatic = CryptoPrivateKeyHandle;
