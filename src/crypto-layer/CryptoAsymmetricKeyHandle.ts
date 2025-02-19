import { SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializableAsync } from "../CryptoSerializable";
import { getProvider } from "./CryptoLayerProviders";

@type("CryptoAsymmetricKeyHandle")
export class CryptoAsymmetricKeyHandle extends CryptoSerializableAsync {
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

    public static async from(value: any): Promise<CryptoAsymmetricKeyHandle> {
        return await this.fromAny(value);
    }

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof CryptoAsymmetricKeyHandle)) {
            throw new CryptoError(CryptoErrorCode.WrongParameters, `Expected 'CryptoAsymmetricKeyHandle'.`);
        }
        const provider = getProvider({ providerName: value.providerName });
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
