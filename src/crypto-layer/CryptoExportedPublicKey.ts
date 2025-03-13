import { serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoSerializable } from "src/CryptoSerializable";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoPublicKeyHandle } from "./CryptoPublicKeyHandle";

/**
 * Represents an exported public key that can be serialized and deserialized.
 * This class provides functionality to export public keys from the crypto layer
 * for storage or transmission, and later import them back into the crypto layer.
 */
@type("CryptoExportedPublicKey")
export class CryptoExportedPublicKey extends CryptoSerializable {
    /**
     * The raw bytes of the public key.
     */
    @validate()
    @serialize()
    public rawPublicKey: CoreBuffer;

    /**
     * The specification of the key pair, including algorithm and other parameters.
     */
    @validate()
    @serialize()
    public spec: KeyPairSpec;

    /**
     * Imports this exported public key into a specific crypto provider and converts it
     * to a concrete public key handle type.
     *
     * @typeparam T - The type of public key handle to create, must extend CryptoPublicKeyHandle.
     * @param constructor - The constructor class with a static method to create the handle from provider and key pair handle.
     * @param providerIdent - Identifier for the crypto provider to use for importing.
     * @returns A Promise that resolves to a new instance of the specified public key handle type.
     */
    public async into<T extends CryptoPublicKeyHandle>(
        constructor: { newFromProviderAndKeyPairHandle(provider: Provider, keyPairHandle: KeyPairHandle): Promise<T> },
        providerIdent: ProviderIdentifier
    ): Promise<T> {
        const provider = getProviderOrThrow(providerIdent);
        const keyPairHandle = await provider.importPublicKey(this.spec, this.rawPublicKey.buffer);
        return await constructor.newFromProviderAndKeyPairHandle(provider, keyPairHandle);
    }

    /**
     * Creates a new CryptoExportedPublicKey from an existing public key handle.
     *
     * @param publicKeyHandle - The public key handle to export.
     * @returns A Promise that resolves to a new CryptoExportedPublicKey containing the exported key data.
     */
    public static async from(publicKeyHandle: CryptoPublicKeyHandle): Promise<CryptoExportedPublicKey> {
        const exportedPublicKey = new CryptoExportedPublicKey();
        exportedPublicKey.spec = publicKeyHandle.spec;
        exportedPublicKey.rawPublicKey = new CoreBuffer(await publicKeyHandle.keyPairHandle.getPublicKey());
        return exportedPublicKey;
    }
}
