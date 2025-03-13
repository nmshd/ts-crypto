import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import {
    CryptoPrivateStateHandle,
    ICryptoPrivateStateHandle,
    ICryptoPrivateStateHandleSerialized
} from "./CryptoPrivateStateHandle";

/**
 * Interface defining the serialized form of {@link CryptoPrivateStateTransmitHandle}.
 */
export interface ICryptoPrivateStateTransmitHandleSerialized extends ICryptoPrivateStateHandleSerialized {}

/**
 * Interface defining the structure of {@link CryptoPrivateStateTransmitHandle}.
 */
export interface ICryptoPrivateStateTransmitHandle extends ICryptoPrivateStateHandle {}

/**
 * Represents a handle to a private state specifically for transmitting cryptographic messages
 * within the crypto layer. This handle extends {@link CryptoPrivateStateHandle} and is specialized
 * for transmit operations, managing state properties without exposing key material.
 * It extends {@link CryptoSerializableAsync} to support asynchronous serialization and deserialization.
 */
@type("CryptoPrivateStateTransmitHandle")
export class CryptoPrivateStateTransmitHandle
    extends CryptoPrivateStateHandle
    implements ICryptoPrivateStateTransmitHandle
{
    /**
     * Converts the {@link CryptoPrivateStateTransmitHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoPrivateStateTransmitHandleSerialized} object that is JSON serializable.
     */
    public override async toJSON(verbose = true): Promise<ICryptoPrivateStateTransmitHandleSerialized> {
        const base = await super.toJSON(verbose); // Get the base serialization
        return {
            ...base, // Spread the base properties
            "@type": verbose ? "CryptoPrivateStateTransmitHandle" : undefined
        };
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateTransmitHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoPrivateStateTransmitHandle} and
     * interfaces conforming to {@link ICryptoPrivateStateTransmitHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoPrivateStateTransmitHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateTransmitHandle} instance.
     */
    public static override async from(
        value: CryptoPrivateStateTransmitHandle | ICryptoPrivateStateTransmitHandle
    ): Promise<CryptoPrivateStateTransmitHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateTransmitHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoPrivateStateTransmitHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateTransmitHandle} instance.
     */
    public static override async fromJSON(
        value: ICryptoPrivateStateTransmitHandleSerialized
    ): Promise<CryptoPrivateStateTransmitHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateTransmitHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoPrivateStateTransmitHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateTransmitHandle} instance.
     */
    public static override async fromBase64(value: string): Promise<CryptoPrivateStateTransmitHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
