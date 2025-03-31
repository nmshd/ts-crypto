import { ISerializable, ISerialized, Serializable, serialize, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoPrivateStateHandle } from "../crypto-layer/state/CryptoPrivateStateHandle";
import { CryptoPublicStateHandle } from "../crypto-layer/state/CryptoPublicStateHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPublicState } from "./CryptoPublicState";
import { CryptoStateType } from "./CryptoStateType";

/**
 * Describes how a private state is serialized.
 */
export interface ICryptoPrivateStateSerialized extends ISerialized {
    key: string;
    nnc: string;
    cnt: number;
    alg: number;
    id?: string;
    typ: number;
}

/**
 * Interface for a private state in cryptographic operations.
 */
export interface ICryptoPrivateState extends ISerializable {
    secretKey: ICoreBuffer;
    nonce: ICoreBuffer;
    counter: number;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

/**
 * The original libsodium-based implementation for private state, providing
 * direct encryption and decryption with a raw secret key.
 */
export class CryptoPrivateStateWithLibsodium extends Serializable implements ICryptoPrivateState, IClearable {
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
    public secretKey: CoreBuffer;

    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public stateType: CryptoStateType;

    /**
     * Updates the state's internal counter.
     */
    protected setCounter(value: number): void {
        this.counter = value;
    }

    /**
     * Clears sensitive fields in memory.
     */
    public clear(): void {
        this.secretKey.clear();
        this.nonce.clear();
    }

    public override toString(): string {
        return this.serialize();
    }

    /**
     * Returns a public variant of this state (nonce, algorithm, etc., but not the secret key).
     */
    public toPublicState(): CryptoPublicState {
        return CryptoPublicState.from({
            nonce: this.nonce.clone(),
            algorithm: this.algorithm,
            stateType: this.stateType,
            id: this.id
        });
    }

    /**
     * Serializes the private state to JSON.
     */
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        return {
            nnc: this.nonce.toBase64URL(),
            cnt: this.counter,
            key: this.secretKey.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType,
            id: this.id,
            "@type": verbose ? "CryptoPrivateStateWithLibsodium" : undefined
        };
    }

    protected static override preFrom(value: any): any {
        if (value.nnc) {
            value = {
                nonce: value.nnc,
                counter: value.cnt,
                secretKey: value.key,
                algorithm: value.alg,
                stateType: value.typ,
                id: value.id
            };
        }

        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);
        CryptoValidation.checkCounter(value.counter);
        CryptoValidation.checkNonce(value.nonce, value.algorithm);
        CryptoValidation.checkSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        CryptoValidation.checkStateType(value.stateType);

        if (value.id) {
            CryptoValidation.checkId(value.id);
        }
        return value;
    }

    public static from(obj: ICryptoPrivateState): CryptoPrivateStateWithLibsodium {
        return this.fromAny(obj);
    }

    public static fromJSON(value: any): CryptoPrivateStateWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Encrypts the given plaintext, automatically incrementing the counter.
     */
    public async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        const cipher = await CryptoEncryption.encryptWithCounter(
            plaintext,
            this.secretKey,
            this.nonce,
            this.counter,
            this.algorithm
        );
        this.counter++;
        return cipher;
    }

    /**
     * Decrypts the given cipher, verifying the counter (unless omitted).
     */
    public async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        if (!omitCounterCheck) {
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

        const plaintext = await CryptoEncryption.decryptWithCounter(
            cipher,
            this.secretKey,
            this.nonce,
            cipher.counter ?? this.counter,
            this.algorithm
        );

        if (!omitCounterCheck) {
            this.counter++;
        }
        return plaintext;
    }
}

/**
 * Extended private state that delegates encryption and decryption to a handle
 * if available; otherwise, falls back to libsodium-based operations.
 */
export class CryptoPrivateState extends CryptoPrivateStateWithLibsodium {
    /**
     * Encrypts plaintext using either the handle-based approach or libsodium, depending on initialization and key type.
     */
    public override async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            // When using a handle-based key, cast to the handle class for custom logic.
            const handleState = this as unknown as CryptoPrivateStateHandle;
            return await handleState.encrypt(plaintext);
        }
        return await super.encrypt(plaintext);
    }

    /**
     * Decrypts ciphertext using either the handle-based approach or libsodium, depending on initialization and key type.
     */
    public override async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            const handleState = this as unknown as CryptoPrivateStateHandle;
            return await handleState.decrypt(cipher, omitCounterCheck);
        }
        return await super.decrypt(cipher, omitCounterCheck);
    }

    /**
     * Creates a public-state object. If handle-based usage is active, returns a handle-based public state.
     * Otherwise, provides the standard libsodium public state.
     */
    public override toPublicState(): CryptoPublicState | CryptoPublicStateHandle {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            const handleState = this as unknown as CryptoPrivateStateHandle;
            return handleState.toPublicState();
        }
        return super.toPublicState();
    }

    /**
     * Ensures serialization returns `@type: "CryptoPrivateState"`.
     */
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const json = super.toJSON(verbose);
        // Override the @type to ensure proper identification
        json["@type"] = verbose ? "CryptoPrivateState" : undefined;
        return json;
    }
}
