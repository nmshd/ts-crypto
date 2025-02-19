import { serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { getProvider } from "./CryptoLayerProviders";

@type("CryptoAsymmetricKeyHandle")
export class CryptoAsymmetricKeyHandle extends CryptoSerializable {
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

    public static from(value: any): CryptoAsymmetricKeyHandle {
        return this.fromAny(value);
    }

    public static override async postFrom(value: CryptoAsymmetricKeyHandle): Promise<CryptoAsymmetricKeyHandle> {
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
