import { SerializableAsync, type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoValidation } from "../../CryptoValidation";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoStateType } from "../../state/CryptoStateType";
import { getProviderOrThrow } from "../CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
import {
    CryptoPrivateStateHandle,
    ICryptoPrivateStateHandle,
    ICryptoPrivateStateHandleSerialized
} from "./CryptoPrivateStateHandle";
import { CryptoPublicStateHandle } from "./CryptoPublicStateHandle";

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
    public override async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.Unknown, "Cipher is missing a counter.");
        }

        if (!omitCounterCheck && this.counter !== cipher.counter) {
            throw new CryptoError(
                CryptoErrorCode.StateWrongOrder,
                `Expected counter ${this.counter} but got ${cipher.counter}.`
            );
        }

        const plaintext = await CryptoEncryption.decryptWithCounter(
            cipher,
            this.secretKeyHandle,
            this.nonce,
            cipher.counter ?? this.counter,
            this.algorithm
        );

        if (!omitCounterCheck) {
            this.setCounter(this.counter + 1);
        }

        return plaintext;
    }

    public static fromNonce(
        nonce: CoreBuffer,
        secretKeyHandle: CryptoSecretKeyHandle,
        counter = 0
    ): Promise<CryptoPrivateStateReceiveHandle> {
        return this.from({
            nonce: nonce.clone(),
            counter,
            secretKeyHandle,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Receive
        });
    }

    public static fromPublicState(
        publicState: CryptoPublicStateHandle,
        secretKeyHandle: CryptoSecretKeyHandle,
        counter = 0
    ): Promise<CryptoPrivateStateReceiveHandle> {
        return this.from({
            nonce: publicState.nonce.clone(),
            counter,
            secretKeyHandle,
            algorithm: publicState.algorithm,
            id: publicState.id,
            stateType: CryptoStateType.Receive
        });
    }

    /**
     * Converts the {@link CryptoPrivateStateReceiveHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoPrivateStateReceiveHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoPrivateStateReceiveHandleSerialized {
        const base = super.toJSON(verbose); // Get the base serialization
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

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof CryptoPrivateStateReceiveHandle)) {
            throw new CryptoError(
                CryptoErrorCode.WrongParameters,
                "Expected 'CryptoPrivateStateReceiveHandle' in postFrom."
            );
        }
        const provider = getProviderOrThrow({ providerName: value.secretKeyHandle.providerName });
        const keyHandle = await provider.loadKey(value.secretKeyHandle.id);

        value.secretKeyHandle.keyHandle = keyHandle;
        value.secretKeyHandle.provider = provider;
        return value;
    }
}
