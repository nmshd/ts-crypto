import { type } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, Encoding } from "../CoreBuffer";
import { CryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";

export interface ICryptoPublicKeyHandle {
    keyPairHandle: KeyPairHandle;
    spec: KeyPairSpec;
    providerName: string;
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
}

/**
 * Implementation of a public key handle for cryptographic operations using the crypto layer.
 * This class provides methods to convert between different key formats and create key handles
 * from various sources.
 */
@type("CryptoPublicKeyHandle")
export class CryptoPublicKeyHandle extends CryptoAsymmetricKeyHandle implements ICryptoPublicKeyHandle {
    /**
     * Serializes the public key to a URL-safe Base64 string without padding.
     * This format is suitable for use in URLs and other contexts where special characters
     * might cause issues.
     *
     * @returns A Promise that resolves to the serialized string representation of the public key.
     */
    public async toSerializedString(): Promise<string> {
        const raw = await this.keyPairHandle.getPublicKey();
        return CoreBuffer.from(raw).toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    /**
     * Exports the public key in PEM format.
     * PEM (Privacy Enhanced Mail) is a common format for storing and exchanging cryptographic keys.
     *
     * @returns A Promise that resolves to the PEM-encoded string representation of the public key.
     */
    public async toPEM(): Promise<string> {
        const raw = await this.keyPairHandle.getPublicKey();
        return CoreBuffer.from(raw).toString(Encoding.Pem, "PRIVATE KEY");
    }

    /**
     * Creates a public key handle from a string representation with the specified encoding.
     *
     * @param providerIdent - Identifier for the crypto provider to be used.
     * @param value - The string representation of the public key.
     * @param spec - Specification for the key, including algorithm and parameters.
     * @param encoding - The encoding format used for the string representation.
     * @returns A Promise that resolves to a new CryptoPublicKeyHandle.
     */
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

    /**
     * Creates a public key handle from a PEM-encoded string.
     * This is a convenience method that calls fromString with Encoding.Pem.
     *
     * @param providerIdent - Identifier for the crypto provider to be used.
     * @param pem - The PEM-encoded string representation of the public key.
     * @param spec - Specification for the key, including algorithm and parameters.
     * @returns A Promise that resolves to a new CryptoPublicKeyHandle.
     */
    public static async fromPEM(
        providerIdent: ProviderIdentifier,
        pem: string,
        spec: KeyPairSpec
    ): Promise<CryptoPublicKeyHandle> {
        return await CryptoPublicKeyHandle.fromString(providerIdent, pem, spec, Encoding.Pem);
    }
}
