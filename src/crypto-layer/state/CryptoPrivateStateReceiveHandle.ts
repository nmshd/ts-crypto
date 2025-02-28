import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import {
    CryptoPrivateStateHandle,
    ICryptoPrivateStateHandle,
    ICryptoPrivateStateHandleSerialized
} from "./CryptoPrivateStateHandle";

/**
 * Interface defining the serialized form of {@link CryptoPrivateStateReceiveHandle}.
 */
export interface ICryptoPrivateStateReceiveHandleSerialized extends ICryptoPrivateStateHandleSerialized {}

/**
 * Interface defining the structure of {@link CryptoPrivateStateReceiveHandle}.
 */
export interface ICryptoPrivateStateReceiveHandle extends ICryptoPrivateStateHandle {}

/**
 * Represents a handle to a private state specifically for receiving cryptographic messages
 * within the crypto layer. This handle extends {@link CryptoPrivateStateHandle} and is specialized
 * for receive operations, managing state properties without exposing key material.
 * It extends {@link CryptoSerializableAsync} to support asynchronous serialization and deserialization.
 */
@type("CryptoPrivateStateReceiveHandle")
export class CryptoPrivateStateReceiveHandle
    extends CryptoPrivateStateHandle
    implements ICryptoPrivateStateReceiveHandle
{
    // No longer needed, inherited from base class
    // public secretKeyHandle: CryptoSecretKeyHandle;

    /**
     * Converts the {@link CryptoPrivateStateReceiveHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoPrivateStateReceiveHandleSerialized} object that is JSON serializable.
     */
    public override async toJSON(verbose = true): Promise<ICryptoPrivateStateReceiveHandleSerialized> {
        const base = await super.toJSON(verbose); // Get the base serialization
        return {
            ...base, // Spread the base properties
            "@type": verbose ? "CryptoPrivateStateReceiveHandle" : undefined 
        };
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateReceiveHandle} instance from a generic value.
     * This method is designed to handle both instances of {@link CryptoPrivateStateReceiveHandle} and
     * interfaces conforming to {@link ICryptoPrivateStateReceiveHandle}.
     *
     * @param value - The value to be converted into a {@link CryptoPrivateStateReceiveHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateReceiveHandle} instance.
     */
    public static override async from(
        value: CryptoPrivateStateReceiveHandle | ICryptoPrivateStateReceiveHandle
    ): Promise<CryptoPrivateStateReceiveHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateReceiveHandle} from a JSON object.
     *
     * @param value - JSON object representing the serialized {@link CryptoPrivateStateReceiveHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateReceiveHandle} instance.
     */
    public static override async fromJSON(
        value: ICryptoPrivateStateReceiveHandleSerialized
    ): Promise<CryptoPrivateStateReceiveHandle> {
        return await this.fromAny(value);
    }

    /**
     * Asynchronously creates a {@link CryptoPrivateStateReceiveHandle} from a Base64 encoded string.
     *
     * @param value - Base64 encoded string representing the serialized {@link CryptoPrivateStateReceiveHandle}.
     * @returns A Promise that resolves to a {@link CryptoPrivateStateReceiveHandle} instance.
     */
    public static override async fromBase64(value: string): Promise<CryptoPrivateStateReceiveHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
