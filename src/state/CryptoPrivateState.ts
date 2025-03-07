import { ISerializable, ISerialized, Serializable, serialize, validate } from "@js-soft/ts-serval";
import { CryptoSecretKeyHandle } from "src/crypto-layer/encryption/CryptoSecretKeyHandle";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoPrivateStateHandle } from "../crypto-layer/state/CryptoPrivateStateHandle";
import { CryptoPublicStateHandle } from "../crypto-layer/state/CryptoPublicStateHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPublicState } from "./CryptoPublicState";
import { CryptoStateType } from "./CryptoStateType";

export interface ICryptoPrivateStateSerialized extends ISerialized {
    key: string;
    nnc: string;
    cnt: number;
    alg: number;
    id?: string;
    typ: number;
}

export interface ICryptoPrivateState extends ISerializable {
    secretKey: ICoreBuffer;
    nonce: ICoreBuffer;
    counter: number;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

/**
 * The original libsodium-based private state, now renamed to CryptoPrivateStateWithLibsodium.
 * It can encrypt/decrypt using raw secretKey (libsodium) logic.
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

    protected setCounter(value: number): void {
        this.counter = value;
    }

    public clear(): void {
        this.secretKey.clear();
        this.nonce.clear();
    }

    public override toString(): string {
        return this.serialize();
    }

    public toPublicState(): CryptoPublicState {
        return CryptoPublicState.from({
            nonce: this.nonce.clone(),
            algorithm: this.algorithm,
            stateType: this.stateType,
            id: this.id
        });
    }

    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        return {
            nnc: this.nonce.toBase64URL(),
            cnt: this.counter,
            key: this.secretKey.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType,
            id: this.id,
            "@type": verbose ? "CryptoPrivateState" : undefined
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
 * A simple flag to indicate if a handle-based approach is possible (mirroring your encryption extension's pattern).
 */
let privateStateProviderInitialized = false;

/**
 * Call this to initialize handle-based usage for private states if a provider is available.
 */
export function initCryptoPrivateState(): void {
    privateStateProviderInitialized = true;
}

/**
 * Extended class that checks if the private state is handle-based (i.e. an instance of
 * CryptoPrivateStateHandle) and, if so, delegates encryption/decryption to the handle logic.
 * Otherwise, it calls the libsodium fallback from CryptoPrivateStateWithLibsodium.
 */
export class CryptoPrivateState extends CryptoPrivateStateWithLibsodium {
    public override async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        if (privateStateProviderInitialized && this.secretKey instanceof CryptoSecretKeyHandle) {
            const handleState = this as unknown as CryptoPrivateStateHandle;
            return await handleState.encrypt(plaintext);
        }
        return await super.encrypt(plaintext);
    }

    public override async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        if (privateStateProviderInitialized && this.secretKey instanceof CryptoSecretKeyHandle) {
            const handleState = this as unknown as CryptoPrivateStateHandle;
            return await handleState.decrypt(cipher, omitCounterCheck);
        }
        return await super.decrypt(cipher, omitCounterCheck);
    }

    /**
     * Overridden method for returning a public state. If we're handle-based and the provider is
     * initialized, we construct a `CryptoPublicStateHandle`. Otherwise, fall back to the libsodium approach.
     */
    public override toPublicState(): CryptoPublicState | CryptoPublicStateHandle {
        if (privateStateProviderInitialized && this.secretKey instanceof CryptoSecretKeyHandle) {
            // Build a new handle-based public state
            const handleState = this as unknown as CryptoPrivateStateHandle;
            return handleState.toPublicState();
        }
        // Fallback to the libsodium-based method
        return super.toPublicState();
    }

    /**
     * Ensures that CryptoPrivateState serializes correctly with `@type: "CryptoPrivateState"`
     * instead of `@type: "CryptoPrivateStateWithLibsodium"`
     */
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const json = super.toJSON(verbose);
        json["@type"] = verbose ? "CryptoPrivateState" : undefined;
        return json;
    }
}
