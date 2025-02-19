import { SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializableAsync } from "../CryptoSerializable";
import { getProvider } from "./CryptoLayerProviders";

/**
 * Loose check if `value` can be initialized as if it was a `CryptoAsymmetricKeyHandle`.
 */
function isCryptoAsymmetricKeyHandle(value: any): value is CryptoAsymmetricKeyHandle {
    return typeof value["providerName"] === "string" && typeof value["id"] === "string";
}

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

    protected static async newFromProviderAndKeyPairHandle<T extends CryptoAsymmetricKeyHandle>(
        this: new () => T,
        provider: Provider,
        keyPairHandle: KeyPairHandle,
        other?: {
            providerName?: string;
            keyId?: string;
            keySpec?: KeyPairSpec;
        }
    ): Promise<T> {
        const result = new this();

        result.providerName = other?.providerName ?? (await provider.providerName());
        result.id = other?.keyId ?? (await keyPairHandle.id());
        result.spec = other?.keySpec ?? (await keyPairHandle.spec());

        result.provider = provider;
        result.keyPairHandle = keyPairHandle;
        return result;
    }

    public static async from(value: any): Promise<CryptoAsymmetricKeyHandle> {
        return await this.fromAny(value);
    }

    public static async fromBase64(value: string): Promise<CryptoAsymmetricKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!isCryptoAsymmetricKeyHandle(value)) {
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
