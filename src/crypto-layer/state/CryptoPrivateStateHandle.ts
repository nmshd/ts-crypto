import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoStateType } from "../../state/CryptoStateType";
import { CryptoEncryptionWithCryptoLayer } from "../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
import { CryptoPublicStateHandle } from "./CryptoPublicStateHandle";

/**
 * Interface defining the serialized form of {@link CryptoPrivateStateHandle}.
 */
export interface ICryptoPrivateStateHandleSerialized extends ISerialized {
    key: string; // Key is required in serialized form
    nnc: string;
    cnt: number;
    alg: number;
    id?: string;
    typ: number;
}

/**
 * Interface defining the structure of {@link CryptoPrivateStateHandle}.
 */
export interface ICryptoPrivateStateHandle extends ISerializable {
    nonce: CoreBuffer;
    counter: number;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
    secretKeyHandle: CryptoSecretKeyHandle;
}

/**
 * Represents a handle to a private state for cryptographic operations within the crypto layer.
 * This class includes encryption/decryption methods that use the crypto-layer approach,
 * as well as a method to derive a corresponding {@link CryptoPublicStateHandle}.
 * It extends {@link CryptoSerializableAsync} to support asynchronous serialization/deserialization.
 */
@type("CryptoPrivateStateHandle")
export class CryptoPrivateStateHandle extends CryptoSerializableAsync implements ICryptoPrivateStateHandle {
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    @validate()
    @serialize()
    public counter: number;

    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public stateType: CryptoStateType;

    @validate()
    @serialize({ alias: "key" })
    public secretKeyHandle: CryptoSecretKeyHandle;

    /**
     * Updates the state's internal counter.
     */
    protected setCounter(value: number): void {
        this.counter = value;
    }

    /**
     * Converts the {@link CryptoPrivateStateHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoPrivateStateHandleSerialized} object that is JSON serializable.
     */
    public override async toJSON(verbose = true): Promise<ICryptoPrivateStateHandleSerialized> {
        return {
            nnc: this.nonce.toBase64URL(),
            cnt: this.counter,
            alg: this.algorithm,
            typ: this.stateType,
            id: this.id,
            key: await this.secretKeyHandle.toSerializedString(),
            "@type": verbose ? "CryptoPrivateStateHandle" : undefined
        };
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateHandle} instance from a generic value.
     */
    public static async from(
        value: CryptoPrivateStateHandle | ICryptoPrivateStateHandle
    ): Promise<CryptoPrivateStateHandle> {
        return await this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.nnc) {
            value = {
                nonce: value.nnc,
                counter: value.cnt,
                algorithm: value.alg,
                stateType: value.typ,
                id: value.id,
                secretKeyHandle: value.key
            };
        }
        return value;
    }

    public static async fromJSON(value: ICryptoPrivateStateHandleSerialized): Promise<CryptoPrivateStateHandle> {
        return await this.fromAny(value);
    }

    public static async fromBase64(value: string): Promise<CryptoPrivateStateHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Encrypts the provided plaintext using this handle’s key material, incrementing the counter
     * (mirroring transmit state logic). The result is a {@link CryptoCipher} containing the ciphertext (and the new counter).
     *
     * @param plaintext - The content to encrypt.
     * @returns A Promise resolving to a CryptoCipher with the resulting ciphertext.
     */
    public async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        try {
            const cipher = await CryptoEncryptionWithCryptoLayer.encryptWithCounter(
                plaintext,
                this.secretKeyHandle,
                this.nonce,
                this.counter
            );
            // After successful encryption, increment our local counter.
            this.counter++;
            return cipher;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionEncrypt, `State handle encrypt error: ${e}`);
        }
    }

    /**
     * Decrypts the provided ciphertext using this handle’s key material, comparing counters if needed
     * (mirroring receive state logic).
     *
     * @param cipher - The cipher to decrypt (which may have a counter).
     * @param omitCounterCheck - If true, skip the counter check. Otherwise, require cipher.counter to match our current counter.
     * @returns A Promise resolving to the decrypted plaintext.
     */
    public async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        try {
            if (!omitCounterCheck) {
                // If the cipher has no counter or does not match, throw
                if (typeof cipher.counter === "undefined") {
                    throw new CryptoError(CryptoErrorCode.StateWrongCounter, "Cipher has no counter set.");
                }
                if (this.counter !== cipher.counter) {
                    throw new CryptoError(
                        CryptoErrorCode.StateWrongOrder,
                        `Expected counter=${this.counter}, got ${cipher.counter}.`
                    );
                }
            }
            const plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                cipher,
                this.secretKeyHandle,
                this.nonce,
                cipher.counter ?? this.counter
            );
            if (!omitCounterCheck) {
                this.counter++;
            }
            return plaintext;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.EncryptionDecrypt, `State handle decrypt error: ${e}`);
        }
    }

    /**
     * Creates a new {@link CryptoPublicStateHandle} representing the public portion of this handle.
     *
     * @returns A new CryptoPublicStateHandle that contains the public fields (id, nonce, algorithm, stateType).
     */
    public toPublicState(): CryptoPublicStateHandle {
        const publicState = new CryptoPublicStateHandle();
        publicState.id = this.id;
        publicState.nonce = this.nonce.clone();
        publicState.algorithm = this.algorithm;
        publicState.stateType = this.stateType;
        return publicState;
    }
}
