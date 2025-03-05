import { SerializableAsync, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, Encoding } from "src/CoreBuffer";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";

export interface ICryptoPublicKeyHandle {
    keyPairHandle: KeyPairHandle;
    spec: KeyPairSpec;
    providerName: string;
    rawPublicKey?: CoreBuffer;
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

function isKeyPairSpec(value: any): value is KeyPairSpec {
    return (
        (typeof value.cipher === "string" || value.cipher === null) &&
        typeof value.asym_spec === "string" &&
        typeof value.signing_hash === "string" &&
        typeof value.ephemeral === "boolean" &&
        typeof value.non_exportable === "boolean"
    );
}

function isCryptoPublicKeyHandle(value: any): value is CryptoPublicKeyHandle {
    return (
        typeof value.id === "string" &&
        typeof value.providerName === "string" &&
        (value.rawPublicKey instanceof CoreBuffer || typeof value.rawPublicKey === "undefined") &&
        isKeyPairSpec(value.spec)
    );
}

@type("CryptoPublicKeyHandle")
export class CryptoPublicExportableKeyHandle extends CryptoAsymmetricKeyHandle implements ICryptoPublicKeyHandle {
    @validate({ nullable: true })
    @serialize()
    public rawPublicKey?: CoreBuffer;

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!isCryptoPublicKeyHandle(value)) {
            throw new CryptoError(CryptoErrorCode.WrongParameters, `Expected 'CryptoPublicKeyHandle'.`);
        }
        if (value.spec.non_exportable && value.rawPublicKey) {
            throw new CryptoError(
                CryptoErrorCode.WrongParameters,
                `Public key is non extractable but a raw public key was supplied.`
            );
        }

        const provider = getProviderOrThrow({ providerName: value.providerName });
        const keyHandle = value.rawPublicKey
            ? await provider.importPublicKey(value.spec, value.rawPublicKey.buffer)
            : await provider.loadKeyPair(value.id);

        value.keyPairHandle = keyHandle;
        value.provider = provider;
        return value;
    }

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
