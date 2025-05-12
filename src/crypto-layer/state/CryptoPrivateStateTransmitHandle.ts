import { SerializableAsync, type } from "@js-soft/ts-serval";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoValidation } from "src/CryptoValidation";
import { CryptoCipher } from "src/encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "src/encryption/CryptoEncryption";
import { CryptoStateType } from "src/state/CryptoStateType";
import { CoreBuffer } from "../../CoreBuffer";
import { getProviderOrThrow } from "../CryptoLayerProviders";
import { CryptoEncryptionWithCryptoLayer } from "../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
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
    public static async generate(
        secretKey: CryptoSecretKeyHandle,
        id?: string,
        algorithm?: CryptoEncryptionAlgorithm
    ): Promise<CryptoPrivateStateTransmitHandle> {
        if (algorithm) {
            CryptoValidation.checkEncryptionAlgorithm(algorithm);
            CryptoValidation.checkKeyHandleForAlgorithm(secretKey, algorithm);
        }
        const currentAlgorithm = CryptoEncryptionAlgorithm.fromCalCipher(secretKey.spec.cipher);
        const nonce = await CryptoEncryptionWithCryptoLayer.createNonce(currentAlgorithm, secretKey.provider);
        const counter = 0;

        return await this.from({
            nonce,
            counter,
            algorithm: currentAlgorithm,
            id,
            stateType: CryptoStateType.Transmit,
            secretKeyHandle: secretKey
        });
    }

    public override async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        const cipher = await CryptoEncryption.encryptWithCounter(
            plaintext,
            this.secretKeyHandle,
            this.nonce,
            this.counter,
            this.algorithm
        );
        this.setCounter(this.counter + 1);
        return cipher;
    }

    public override async decrypt(cipher: CryptoCipher): Promise<CoreBuffer> {
        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") throw new CryptoError(CryptoErrorCode.StateWrongCounter);

        const plaintext = await CryptoEncryption.decryptWithCounter(
            cipher,
            this.secretKeyHandle,
            this.nonce,
            cipher.counter
        );
        return plaintext;
    }

    /**
     * Converts the {@link CryptoPrivateStateTransmitHandle} object into a JSON serializable object.
     *
     * @param verbose - If `true`, includes the `@type` property in the JSON output. Defaults to `true`.
     * @returns An {@link ICryptoPrivateStateTransmitHandleSerialized} object that is JSON serializable.
     */
    public override toJSON(verbose = true): ICryptoPrivateStateTransmitHandleSerialized {
        const base = super.toJSON(verbose); // Get the base serialization
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

    public static override async postFrom<T extends SerializableAsync>(value: T): Promise<T> {
        if (!(value instanceof CryptoPrivateStateTransmitHandle)) {
            throw new CryptoError(
                CryptoErrorCode.WrongParameters,
                "Expected 'CryptoPrivateStateTransmitHandle' in postFrom."
            );
        }
        const provider = getProviderOrThrow({ providerName: value.secretKeyHandle.providerName });
        const keyHandle = await provider.loadKey(value.secretKeyHandle.id);

        value.secretKeyHandle.keyHandle = keyHandle;
        value.secretKeyHandle.provider = provider;
        return value;
    }
}
