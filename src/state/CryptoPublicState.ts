import { ISerializable, ISerialized, Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoPublicStateHandle } from "../crypto-layer/state/CryptoPublicStateHandle";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoStateType } from "./CryptoStateType";

/**
 * Describes the serialized form of a public state.
 */
export interface ICryptoPublicStateSerialized extends ISerialized {
    nnc: string;
    alg: number;
    id?: string;
    typ: number;
}

/**
 * Defines the public state properties needed for cryptographic operations.
 */
export interface ICryptoPublicState extends ISerializable {
    nonce: CoreBuffer;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

/**
 * Original libsodium-based public state logic, renamed to preserve
 * functionality when no handle-based provider is used.
 */
@type("CryptoPublicStateWithLibsodium")
export class CryptoPublicStateWithLibsodium extends Serializable implements ICryptoPublicState, IClearable {
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public stateType: CryptoStateType;

    /**
     * Clears any sensitive data.
     */
    public clear(): void {
        this.nonce.clear();
    }

    /**
     * Serializes this object to JSON. Uses a distinct `@type` to differentiate from the extended class.
     */
    public override toJSON(verbose = true): ICryptoPublicStateSerialized {
        return {
            "@type": verbose ? "CryptoPublicStateWithLibsodium" : undefined,
            nnc: this.nonce.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType,
            id: this.id
        };
    }

    /**
     * Prepares a raw object for conversion into a CryptoPublicStateWithLibsodium instance.
     */
    protected static override preFrom(value: any): any {
        if (value.nnc) {
            value = {
                nonce: value.nnc,
                algorithm: value.alg,
                stateType: value.typ,
                id: value.id
            };
        }

        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);
        CryptoValidation.checkStateType(value.stateType);
        CryptoValidation.checkNonce(value.nonce, value.algorithm);

        return value;
    }

    public static from(value: CryptoPublicState | ICryptoPublicState): CryptoPublicStateWithLibsodium {
        return this.fromAny(value);
    }

    public static fromJSON(value: ICryptoPublicStateSerialized): CryptoPublicStateWithLibsodium {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoPublicStateWithLibsodium {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}

/**
 * Extended public state that can produce a handle-based version if a provider is initialized.
 * Otherwise, it behaves like the original libsodium-based version.
 */
@type("CryptoPublicState")
export class CryptoPublicState extends CryptoPublicStateWithLibsodium {
    /**
     * Overrides JSON serialization to ensure `@type` is "CryptoPublicState".
     */
    public override toJSON(verbose = true): ICryptoPublicStateSerialized {
        const obj = super.toJSON(false);
        obj["@type"] = verbose ? "CryptoPublicState" : undefined;
        return obj;
    }

    /**
     * Example method that converts this instance to a handle-based public state, if available.
     * If no provider is initialized, returns the current instance.
     */
    public toHandle(): CryptoPublicStateHandle {
        const handleState = new CryptoPublicStateHandle();
        handleState.id = this.id;
        handleState.nonce = this.nonce.clone();
        handleState.algorithm = this.algorithm;
        handleState.stateType = this.stateType;
        return handleState;
    }

    /**
     * Converts various forms (raw object or another instance) to an extended CryptoPublicState instance.
     */
    public static override from(value: CryptoPublicState | ICryptoPublicState): CryptoPublicState {
        const base = super.fromAny(value);

        const extended = new CryptoPublicState();
        extended.id = base.id;
        extended.nonce = base.nonce;
        extended.algorithm = base.algorithm;
        extended.stateType = base.stateType;

        return extended;
    }

    /**
     * Converts a serialized form into an extended CryptoPublicState instance.
     */
    public static override fromJSON(value: ICryptoPublicStateSerialized): CryptoPublicState {
        const base = super.fromAny(value);

        const extended = new CryptoPublicState();
        extended.id = base.id;
        extended.nonce = base.nonce;
        extended.algorithm = base.algorithm;
        extended.stateType = base.stateType;

        return extended;
    }

    /**
     * Converts a Base64-encoded string into an extended CryptoPublicState instance.
     */
    public static override fromBase64(value: string): CryptoPublicState {
        const base = super.fromBase64(value);

        const extended = new CryptoPublicState();
        extended.id = base.id;
        extended.nonce = base.nonce;
        extended.algorithm = base.algorithm;
        extended.stateType = base.stateType;

        return extended;
    }
}
