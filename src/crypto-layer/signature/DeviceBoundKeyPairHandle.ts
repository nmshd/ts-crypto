import { ISerializable, ISerialized, SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, Provider } from "@nmshd/rs-crypto-types";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { getProvider } from "../CryptoLayerProviders";

export interface IDeviceBoundKeyPairHandleSerialized extends ISerialized {
    kid: string;
    pnm: string;
}

export interface IDeviceBoundKeyPairHandle extends ISerializable {
    id: string;
    providerName: string;
}

@type("DeviceBoundKeyPairHandle")
export class DeviceBoundKeyPairHandle extends CryptoSerializableAsync implements IDeviceBoundKeyPairHandle {
    @validate()
    @serialize()
    public id: string;

    @validate()
    @serialize()
    public providerName: string;

    public provider: Provider;
    public keyPairHandle: KeyPairHandle;

    protected static override preFrom(value: any): any {
        if (value.kid) {
            value = {
                id: value.kid,
                providerName: value.pnm,
                spec: value.spc
            };
        }

        return value;
    }

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof this)) {
            throw new CryptoError(
                CryptoErrorCode.DeserializeValidation,
                "Expected 'DeviceBoundKeyPairHandle' in postFrom."
            );
        }

        const provider = getProvider({ providerName: value.providerName });
        let keyPairHandle: KeyPairHandle;
        try {
            keyPairHandle = await provider.loadKeyPair(value.id);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.CalLoadKey,
                "Failed to load key during deserialization.",
                undefined,
                e as Error,
                DeviceBoundKeyPairHandle.postFrom
            );
        }

        value.keyPairHandle = keyPairHandle;
        value.provider = provider;
        return value;
    }
}
