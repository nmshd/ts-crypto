import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, IClearable } from "../../CoreBuffer";
import { CryptoPublicKeyHandle } from "../CryptoPublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoExchangePublicKeyHandle}.
 */
export interface ICryptoExchangePublicKeyHandleSerialized extends ISerialized {
    spc: KeyPairSpec; // Specification/Config of key pair stored.
    cid: string; // Crypto layer key pair id used for loading key from a provider.
    pnm: string; // Provider name
}

/**
 * Interface defining the structure of {@link CryptoExchangePublicKeyHandle}.
 */
export interface ICryptoExchangePublicKeyHandle extends ISerializable {
    spec: KeyPairSpec;
    id: string;
    providerName: string;
}

/**
 * Represents a handle to a public key used for cryptographic key exchange operations within the crypto layer.
 * This class extends {@link CryptoPublicKeyHandle} and provides a type-specific implementation for exchange public keys.
 * It encapsulates the key specification, crypto layer key pair ID, and the provider name, allowing for
 * secure and efficient management of public keys without exposing the raw key material.
 */
@type("CryptoExchangePublicKeyHandle")
export class CryptoExchangePublicKeyHandle
    extends CryptoPublicKeyHandle
    implements ICryptoExchangePublicKeyHandle, IClearable
{
    /**
     * Clears sensitive data associated with this public key.
     * Since this class only contains a handle to a key managed by the crypto provider,
     * no actual clearing of raw key material is performed here.
     */
    public clear(): void {
        // No-op for handle objects as they don't contain the actual key material
        // The actual key material is managed by the crypto provider
    }

    /**
     * Converts the {@link CryptoExchangePublicKeyHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoExchangePublicKeyHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoExchangePublicKeyHandleSerialized {
        return {
            spc: this.spec,
            cid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "CryptoExchangePublicKeyHandle" : undefined
        };
    }

    /**
     * Converts the {@link CryptoExchangePublicKeyHandle} object into a Base64 encoded string.
     *
     * @param verbose - If `true`, includes verbose information in the serialized output. Defaults to `true`.
     * @returns A Base64 encoded string representing the serialized {@link CryptoExchangePublicKeyHandle}.
     */
    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Asynchronously creates a {@link CryptoExchangePublicKeyHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoExchangePublicKeyHandle} and
     * interfaces conforming to {@link ICryptoExchangePublicKeyHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoExchangePublicKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangePublicKeyHandle} instance.
     */
    public static override async from(
        value: CryptoExchangePublicKeyHandle | ICryptoExchangePublicKeyHandle
    ): Promise<CryptoExchangePublicKeyHandle> {
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
     * Asynchronously creates a {@link CryptoExchangePublicKeyHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoExchangePublicKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangePublicKeyHandle} instance.
     */
    public static async fromJSON(
        value: ICryptoExchangePublicKeyHandleSerialized
    ): Promise<CryptoExchangePublicKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoExchangePublicKeyHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoExchangePublicKeyHandle}.
     * @returns A Promise that resolves to a {@link CryptoExchangePublicKeyHandle} instance.
     */
    public static override async fromBase64(value: string): Promise<CryptoExchangePublicKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
