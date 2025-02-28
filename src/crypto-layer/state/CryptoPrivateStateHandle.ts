import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoStateType } from "../../state/CryptoStateType";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";

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
 * This abstract class provides a base for more specific private state handles,
 * encapsulating common properties like nonce, counter, and algorithm, without exposing
 * sensitive key material. It extends {@link CryptoSerializableAsync} to support
 * asynchronous serialization and deserialization.
 */
@type("CryptoPrivateStateHandle")
export class CryptoPrivateStateHandle extends CryptoSerializableAsync implements ICryptoPrivateStateHandle {
    /**
     * An optional ID for the private state.
     */
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    /**
     * Nonce (number used once) for stateful encryption/decryption operations.
     */
    @validate()
    @serialize()
    public nonce: CoreBuffer;

    /**
     * Counter for stateful encryption/decryption operations, ensuring message order.
     */
    @validate()
    @serialize()
    public counter: number;

    /**
     * The encryption algorithm used for the state.
     */
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    /**
     * The type of the crypto state (e.g., Receive, Transmit).
     */
    @validate()
    @serialize()
    public stateType: CryptoStateType;

    @validate()
    @serialize({ alias: "key" })
    public secretKeyHandle: CryptoSecretKeyHandle;

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
     * This method is designed to handle both instances of {@link CryptoPrivateStateHandle} and
     * interfaces conforming to {@link ICryptoPrivateStateHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoPrivateStateHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateHandle} instance.
     */
    public static async from(
        value: CryptoPrivateStateHandle | ICryptoPrivateStateHandle
    ): Promise<CryptoPrivateStateHandle> {
        return await this.fromAny(value);
    }

    /**
     * Hook method called before the `from` method during deserialization.
     * It performs pre-processing and validation of the input value.
     *
     * @param value - The value being deserialized.
     * @returns The processed value.
     */
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

    /**
     * Asynchronously creates a {@link CryptoPrivateStateHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoPrivateStateHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateHandle} instance.
     */
    public static async fromJSON(value: ICryptoPrivateStateHandleSerialized): Promise<CryptoPrivateStateHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoPrivateStateHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoPrivateStateHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
