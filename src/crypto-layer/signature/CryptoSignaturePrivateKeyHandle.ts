import { ISerializable, ISerialized, type } from "@js-soft/ts-serval";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoPrivateKeyHandle } from "../CryptoPrivateKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "./CryptoSignaturePublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoSignaturePrivateKeyHandle}.
 */
export interface ICryptoSignaturePrivateKeyHandleSerialized extends ISerialized {
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
 * Interface defining the structure of {@link CryptoSignaturePrivateKeyHandle}.
 */
export interface ICryptoSignaturePrivateKeyHandle extends ISerializable {
    spec: KeyPairSpec;
    id: string;
    providerName: string;
}

/**
 * Provides handle-based private key functionalities for signature operations.
 * This class represents a handle to a private key managed by an external crypto provider.
 */
@type("CryptoSignaturePrivateKeyHandle")
export class CryptoSignaturePrivateKeyHandle extends CryptoPrivateKeyHandle {
    /**
     * Clears sensitive data associated with this private key.
     * Since this class only contains a handle to a key managed by the crypto provider,
     * no actual clearing of raw key material is performed.
     */
    public clear(): void {
        // No-op for handle objects as they don't contain the actual key material.
        // The key material is managed securely by the crypto provider.
    }

    /**
     * Serializes the private key handle into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoSignaturePrivateKeyHandleSerialized}.
     */
    public override toJSON(verbose = true): ICryptoSignaturePrivateKeyHandleSerialized {
        return {
            spc: this.spec,
            cid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "CryptoSignaturePrivateKeyHandle" : undefined
        };
    }

    /**
     * Serializes the private key handle into a Base64 encoded string.
     *
     * @param verbose - If true, includes type information in the serialization.
     * @returns A Base64 encoded string representing the serialized private key handle.
     */
    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Derives the corresponding public key handle from this private key handle.
     *
     * @returns A Promise that resolves to a {@link CryptoSignaturePublicKeyHandle}.
     */
    public async toPublicKey(): Promise<CryptoSignaturePublicKeyHandle> {
        return await CryptoSignaturePublicKeyHandle.newFromProviderAndKeyPairHandle(this.provider, this.keyPairHandle, {
            providerName: this.providerName,
            keyId: this.id,
            keySpec: this.spec
        });
    }

    /**
     * Creates an instance of {@link CryptoSignaturePrivateKeyHandle} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoSignaturePrivateKeyHandle} or an instance.
     * @returns A Promise that resolves to a new instance of {@link CryptoSignaturePrivateKeyHandle}.
     */
    public static override async from(
        value: CryptoSignaturePrivateKeyHandle | ICryptoSignaturePrivateKeyHandle
    ): Promise<CryptoSignaturePrivateKeyHandle> {
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
     * Deserializes a JSON object into a {@link CryptoSignaturePrivateKeyHandle} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoSignaturePrivateKeyHandleSerialized}.
     * @returns A Promise that resolves to an instance of {@link CryptoSignaturePrivateKeyHandle}.
     */
    public static async fromJSON(
        value: ICryptoSignaturePrivateKeyHandleSerialized
    ): Promise<CryptoSignaturePrivateKeyHandle> {
        return await this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoSignaturePrivateKeyHandle} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns A Promise that resolves to an instance of {@link CryptoSignaturePrivateKeyHandle}.
     */
    public static override async fromBase64(value: string): Promise<CryptoSignaturePrivateKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
