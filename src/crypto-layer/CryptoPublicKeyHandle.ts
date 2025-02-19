import { type } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, Encoding } from "src/CoreBuffer";
import { CryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";

export interface ICryptoPublicKeyHandle {
    keyPairHandle: KeyPairHandle;
    spec: KeyPairSpec;
    toSerializedString(): Promise<string>;
    toPEM(): Promise<string>;
    toJSON(): Object;
}

export interface ICryptoPublicKeyHandleStatic {
    new (): ICryptoPublicKeyHandle;
    fromPEM(providerIdent: ProviderIdentifier, pem: string, spec: KeyPairSpec): Promise<CryptoPublicKeyHandle>;
    fromString(
        providerIdent: ProviderIdentifier,
        value: string,
        spec: KeyPairSpec,
        encoding: Encoding
    ): Promise<CryptoPublicKeyHandle>;
    // fromNativeKey(key: any, spec: KeyPairSpec): Promise<ICryptoPublicKeyHandle>;
}

@type("CryptoPublicKeyHandle")
export class CryptoPublicKeyHandle extends CryptoAsymmetricKeyHandle implements ICryptoPublicKeyHandle {
    public async toSerializedString(): Promise<string> {
        const raw = await this.keyPairHandle.getPublicKey();
        return CoreBuffer.from(raw).toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    public async toPEM(): Promise<string> {
        const raw = await this.keyPairHandle.getPublicKey();
        return CoreBuffer.from(raw).toString(Encoding.Pem, "PRIVATE KEY");
    }

    public static async fromString(
        providerIdent: ProviderIdentifier,
        value: string,
        spec: KeyPairSpec,
        encoding: Encoding
    ): Promise<CryptoPublicKeyHandle> {
        const raw = CoreBuffer.fromString(value, encoding).buffer;
        const provider = getProviderOrThrow(providerIdent);
        const keyPairHandle = await provider.importPublicKey(spec, raw);
        return await CryptoPublicKeyHandle.newFromProviderAndKeyPairHandle(provider, keyPairHandle, {
            keySpec: spec
        });
    }

    public static async fromPEM(
        providerIdent: ProviderIdentifier,
        pem: string,
        spec: KeyPairSpec
    ): Promise<CryptoPublicKeyHandle> {
        return await CryptoPublicKeyHandle.fromString(providerIdent, pem, spec, Encoding.Pem);
    }
}
