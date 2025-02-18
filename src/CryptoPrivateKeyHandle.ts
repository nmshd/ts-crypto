import { serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { getProvider } from "./CryptoLayerProviders";
import { CryptoSerializable } from "./CryptoSerializable";

export interface ICryptoPrivateKeyHandle {
    keyPairHandle: KeyPairHandle;
    spec: KeyPairSpec;
}

export interface ICryptoPrivateKeyHandleStatic {
    new (): ICryptoPrivateKeyHandle;
    fromNativeKey(key: any, spec: KeyPairSpec): Promise<ICryptoPrivateKeyHandle>;
}

@type("CryptoPrivateKeyHandle")
export class CryptoPrivateKeyHandle extends CryptoSerializable implements ICryptoPrivateKeyHandle {
    @validate()
    @serialize()
    public spec: KeyPairSpec;

    @validate()
    @serialize()
    public id: string;

    @validate()
    @serialize()
    public providerName: string;

    public provider: Provider;

    public keyPairHandle: KeyPairHandle;

    public static from(value: any): CryptoPrivateKeyHandle {
        return this.fromAny(value);
    }

    public static override async postFrom(value: CryptoPrivateKeyHandle): Promise<CryptoPrivateKeyHandle> {
        const provider = getProvider(value.providerName);
        if (!provider) {
            throw new CryptoError(
                CryptoErrorCode.CalFailedLoadingProvider,
                `Failed loading provider ${value.providerName}`
            );
        }
        const keyHandle = await provider.loadKeyPair(value.id);

        value.keyPairHandle = keyHandle;
        value.provider = provider;
        return value;
    }
}
