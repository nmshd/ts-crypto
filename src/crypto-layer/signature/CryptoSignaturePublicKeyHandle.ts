import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, IClearable } from "../../CoreBuffer";
import { CryptoPublicKeyHandle } from "../CryptoPublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoSignaturePublicKeyHandle}.
 */
export interface ICryptoSignaturePublicKeyHandleSerialized extends ISerialized {
    /**
     * Specification/configuration of the key pair.
     */
    spc: KeyPairSpec;
    /**
     * Crypto layer key pair ID used for loading the key from a provider.
     */
    cid: string;
    /**
     * The name of the crypto provider.
     */
    pnm: string;
}

/**
 * Interface defining the structure of {@link CryptoSignaturePublicKeyHandle}.
 */
export interface ICryptoSignaturePublicKeyHandle extends ISerializable {
    spec: KeyPairSpec;
    id: string;
    providerName: string;
}

/**
 * Provides handle-based public key functionalities for signature operations.
 * This class represents a handle to a public key managed by an external crypto provider.
 */
@type("CryptoSignaturePublicKeyHandle")
export class CryptoSignaturePublicKeyHandle
    extends CryptoPublicKeyHandle
    implements ICryptoSignaturePublicKeyHandle, IClearable
{
    /**
     * Clears sensitive data associated with this public key.
     * Since this class only contains a handle to a key managed by the crypto provider,
     * no actual clearing of raw key material is performed.
     */
    public clear(): void {
        // No-op for handle objects as they don't contain the actual key material.
        // The key material is managed securely by the crypto provider.
    }

    /**
     * Serializes the public key handle into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoSignaturePublicKeyHandleSerialized}.
     */
    public override toJSON(verbose = true): ICryptoSignaturePublicKeyHandleSerialized {
        return {
            spc: this.spec,
            cid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "CryptoSignaturePublicKeyHandle" : undefined
        };
    }

    /**
     * Serializes the public key handle into a Base64 encoded string.
     *
     * @param verbose - If true, includes type information in the serialization.
     * @returns A Base64 encoded string representing the serialized public key handle.
     */
    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Creates an instance of {@link CryptoSignaturePublicKeyHandle} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoSignaturePublicKeyHandle} or an instance.
     * @returns A Promise that resolves to a new instance of {@link CryptoSignaturePublicKeyHandle}.
     */
    public static override async from(
        value: CryptoSignaturePublicKeyHandle | ICryptoSignaturePublicKeyHandle
    ): Promise<CryptoSignaturePublicKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Pre-processes the input object to normalize key aliases.
     *
     * @param value - The raw input object.
     * @returns The normalized object.
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
     * Deserializes a JSON object into a {@link CryptoSignaturePublicKeyHandle} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoSignaturePublicKeyHandleSerialized}.
     * @returns A Promise that resolves to an instance of {@link CryptoSignaturePublicKeyHandle}.
     */
    public static async fromJSON(
        value: ICryptoSignaturePublicKeyHandleSerialized
    ): Promise<CryptoSignaturePublicKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoSignaturePublicKeyHandle} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns A Promise that resolves to an instance of {@link CryptoSignaturePublicKeyHandle}.
     */
    public static override async fromBase64(value: string): Promise<CryptoSignaturePublicKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
