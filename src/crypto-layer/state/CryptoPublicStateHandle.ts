import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoStateType } from "../../state/CryptoStateType";

/**
 * Interface defining the serialized form of {@link CryptoPublicStateHandle}.
 */
export interface ICryptoPublicStateHandleSerialized extends ISerialized {
    nnc: string;
    alg: number;
    id?: string;
    typ: number;
}

/**
 * Interface defining the structure of {@link CryptoPublicStateHandle}.
 */
export interface ICryptoPublicStateHandle extends ISerializable {
    nonce: CoreBuffer;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

/**
 * Represents a handle to a public state for cryptographic operations within the crypto layer.
 * This handle encapsulates the state's properties like nonce, algorithm, and type, without
 * exposing any sensitive key material. It extends {@link CryptoSerializableAsync} to support
 * asynchronous serialization and deserialization.
 */
@type("CryptoPublicStateHandle")
export class CryptoPublicStateHandle extends CryptoSerializableAsync implements ICryptoPublicStateHandle {
    /**
     * An optional ID for the public state.
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

    /**
     * Converts the {@link CryptoPublicStateHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoPublicStateHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoPublicStateHandleSerialized {
        return {
            "@type": verbose ? "CryptoPublicStateHandle" : undefined,
            nnc: this.nonce.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType,
            id: this.id
        };
    }

    /**
     * Asynchronously creates a {@link CryptoPublicStateHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoPublicStateHandle} and
     * interfaces conforming to {@link ICryptoPublicStateHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoPublicStateHandle}.
     * @returns A Promise that resolves to a {@link CryptoPublicStateHandle} instance.
     */
    public static async from(
        value: CryptoPublicStateHandle | ICryptoPublicStateHandle
    ): Promise<CryptoPublicStateHandle> {
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
                algorithm: value.alg,
                stateType: value.typ,
                id: value.id
            };
        }

        return value;
    }

    /**
     * Asynchronously creates a {@link CryptoPublicStateHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoPublicStateHandle}.
     * @returns A Promise that resolves to a {@link CryptoPublicStateHandle} instance.
     */
    public static async fromJSON(value: ICryptoPublicStateHandleSerialized): Promise<CryptoPublicStateHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoPublicStateHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoPublicStateHandle}.
     * @returns A Promise that resolves to a {@link CryptoPublicStateHandle} instance.
     */
    public static async fromBase64(value: string): Promise<CryptoPublicStateHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
