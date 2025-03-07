import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, IClearable } from "src/CoreBuffer";
import { CryptoPrivateKeyHandle } from "../CryptoPrivateKeyHandle";
import { CryptoExchangePublicKeyHandle } from "./CryptoExchangePublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoExchangePrivateKeyHandle}.
 */
export interface ICryptoExchangePrivateKeyHandleSerialized extends ISerialized {
    spc: KeyPairSpec; // Specification/Config of key pair stored.
    cid: string; // Crypto layer key pair id used for loading key from a provider.
    pnm: string; // Provider name
}

/**
 * Interface defining the structure of {@link CryptoExchangePrivateKeyHandle}.
 */
export interface ICryptoExchangePrivateKeyHandle extends ISerializable {
    spec: KeyPairSpec;
    id: string;
    providerName: string;
}

/**
 * Represents a handle to a private key used for cryptographic key exchange operations within the crypto layer.
 * This class extends {@link CryptoPrivateKeyHandle} and provides a type-specific implementation for exchange private keys.
 * It securely manages private keys by only storing a reference (handle) to the key material, which is managed by the underlying crypto provider.
 * This approach enhances security by preventing direct access to the raw private key material from the application code.
 */
@type("CryptoExchangePrivateKeyHandle")
export class CryptoExchangePrivateKeyHandle
    extends CryptoPrivateKeyHandle
    implements ICryptoExchangePrivateKeyHandle, IClearable
{
    /**
     * Clears sensitive data associated with this private key.
     * Since this class only contains a handle to a key managed by the crypto provider,
     * no actual clearing of raw key material is performed here.
     */
    public clear(): void {
        // No-op for handle objects as they don't contain the actual key material
        // The actual key material is managed by the crypto provider
    }

    /**
     * Converts the {@link CryptoExchangePrivateKeyHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoExchangePrivateKeyHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoExchangePrivateKeyHandleSerialized {
        return {
            spc: this.spec,
            cid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "CryptoExchangePrivateKeyHandle" : undefined
        };
    }

    /**
     * Converts the {@link CryptoExchangePrivateKeyHandle} object into a Base64 encoded string.
     *
     * @param verbose - If `true`, includes verbose information in the serialized output. Defaults to `true`.
     * @returns A Base64 encoded string representing the serialized {@link CryptoExchangePrivateKeyHandle}.
     */
    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Asynchronously creates a {@link CryptoExchangePublicKeyHandle} corresponding to this private key handle.
     * This method leverages the underlying crypto provider to derive the public key from the private key.
     *
     * @returns A Promise that resolves to a {@link CryptoExchangePublicKeyHandle} instance.
     */
    public async toPublicKey(): Promise<CryptoExchangePublicKeyHandle> {
        return await CryptoExchangePublicKeyHandle.newFromProviderAndKeyPairHandle(this.provider, this.keyPairHandle, {
            providerName: this.providerName,
            keyId: this.id,
            keySpec: this.spec
        });
    }

    /**
     * Asynchronously creates a {@link CryptoExchangePrivateKeyHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoExchangePrivateKeyHandle} and
     * interfaces conforming to {@link ICryptoExchangePrivateKeyHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoExchangePrivateKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangePrivateKeyHandle} instance.
     */
    public static override async from(
        value: CryptoExchangePrivateKeyHandle | ICryptoExchangePrivateKeyHandle
    ): Promise<CryptoExchangePrivateKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Hook method called before the `from` method during deserialization.
     * It performs pre-processing and validation of the input value.
     *
     * @param value - The value being deserialized.
     * @returns The processed value.
     */
    public static override preFrom(value: any): any {
        if (value.cid) {
            value = {
                spec: value.spc,
                id: value.cid,
                providerName: value.pnm
            };
        }

        return value;
    }

    /**
     * Asynchronously creates a {@link CryptoExchangePrivateKeyHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoExchangePrivateKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangePrivateKeyHandle} instance.
     */
    public static async fromJSON(
        value: ICryptoExchangePrivateKeyHandleSerialized
    ): Promise<CryptoExchangePrivateKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoExchangePrivateKeyHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoExchangePrivateKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangePrivateKeyHandle} instance.
     */
    public static override async fromBase64(value: string): Promise<CryptoExchangePrivateKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
