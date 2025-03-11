import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoSerializableAsync } from "src/CryptoSerializable";
import {
    CryptoSignaturePrivateKeyHandle,
    ICryptoSignaturePrivateKeyHandleSerialized
} from "./CryptoSignaturePrivateKeyHandle";
import {
    CryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandleSerialized
} from "./CryptoSignaturePublicKeyHandle";

/**
 * Interface defining the serialized form of {@link CryptoSignatureKeypairHandle}.
 */
export interface ICryptoSignatureKeypairHandleSerialized extends ISerialized {
    pub: ICryptoSignaturePublicKeyHandleSerialized;
    prv: ICryptoSignaturePrivateKeyHandleSerialized;
}

/**
 * Interface defining the structure of {@link CryptoSignatureKeypairHandle}.
 */
export interface ICryptoSignatureKeypairHandle extends ISerializable {
    publicKey: CryptoSignaturePublicKeyHandle;
    privateKey: CryptoSignaturePrivateKeyHandle;
}

/**
 * Provides handle-based signature keypair functionalities.
 * This class encapsulates both the public and private key handles used for signing operations.
 */
@type("CryptoSignatureKeypairHandle")
export class CryptoSignatureKeypairHandle extends CryptoSerializableAsync implements ICryptoSignatureKeypairHandle {
    @validate()
    @serialize()
    public publicKey: CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize()
    public privateKey: CryptoSignaturePrivateKeyHandle;

    /**
     * Serializes the signature keypair handle.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoSignatureKeypairHandleSerialized}.
     */
    public override toJSON(verbose = true): ICryptoSignatureKeypairHandleSerialized {
        return {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false),
            "@type": verbose ? "CryptoSignatureKeypairHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Creates an instance of {@link CryptoSignatureKeypairHandle} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoSignatureKeypairHandle} or an instance.
     * @returns A Promise that resolves to a new instance of {@link CryptoSignatureKeypairHandle}.
     */
    public static async from(
        value: CryptoSignatureKeypairHandle | ICryptoSignatureKeypairHandle
    ): Promise<CryptoSignatureKeypairHandle> {
        return await this.fromAny(value);
    }

    /**
     * Creates a {@link CryptoSignatureKeypairHandle} instance from provided public and private key handles.
     *
     * @param publicKey - The {@link CryptoSignaturePublicKeyHandle}.
     * @param privateKey - The {@link CryptoSignaturePrivateKeyHandle}.
     * @returns A new instance of {@link CryptoSignatureKeypairHandle}.
     */
    public static fromPublicAndPrivateKeys(
        publicKey: CryptoSignaturePublicKeyHandle,
        privateKey: CryptoSignaturePrivateKeyHandle
    ): CryptoSignatureKeypairHandle {
        const keyPair = new this();
        keyPair.privateKey = privateKey;
        keyPair.publicKey = publicKey;
        return keyPair;
    }

    /**
     * Pre-processes the input object to normalize key aliases and validate key specifications.
     *
     * @param value - The raw input object.
     * @returns The normalized object.
     * @throws {@link CryptoError} if the specifications of the private and public key handles do not match.
     */
    protected static override preFrom(value: any): any {
        if (value.pub) {
            value = { publicKey: value.pub, privateKey: value.prv };
        }

        if (value.privateKey && value.privateKey.spec !== value.publicKey.spec) {
            throw new CryptoError(
                CryptoErrorCode.SignatureWrongAlgorithm,
                "Spec of private and public key handles do not match."
            );
        }

        // Strips the neon JsBox. Otherwise ts-serval will use the neon objects for the
        // new CryptoSignatureKeypairHandle and change them in a way that makes them unusable.
        if (value.privateKey.keyPairHandle) {
            value = {
                publicKey: {
                    id: value.publicKey.id,
                    spec: value.publicKey.spec,
                    providerName: value.publicKey.providerName
                },
                privateKey: {
                    id: value.privateKey.id,
                    spec: value.privateKey.spec,
                    providerName: value.privateKey.providerName
                }
            };
        }
        return value;
    }

    /**
     * Clears sensitive data associated with this key pair.
     * Since this class only contains handles to keys managed by the crypto provider,
     * no actual clearing of raw key material is performed here.
     */
    public clear(): void {
        // No-op for handle objects as they don't contain the actual key material
        // The actual key material is managed by the crypto provider
    }

    /**
     * Deserializes a JSON object into a {@link CryptoSignatureKeypairHandle} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoSignatureKeypairHandleSerialized}.
     * @returns A Promise that resolves to an instance of {@link CryptoSignatureKeypairHandle}.
     */
    public static async fromJSON(
        value: ICryptoSignatureKeypairHandleSerialized
    ): Promise<CryptoSignatureKeypairHandle> {
        return await this.fromAny(value);
    }

    /**
     * Deserializes a base64 encoded string into a {@link CryptoSignatureKeypairHandle} instance.
     *
     * @param value - The base64 encoded string.
     * @returns A Promise that resolves to an instance of {@link CryptoSignatureKeypairHandle}.
     */
    public static async fromBase64(value: string): Promise<CryptoSignatureKeypairHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
