import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoEncryptionWithCryptoLayer } from "../crypto-layer/encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoPrivateStateReceiveHandle } from "../crypto-layer/state/CryptoPrivateStateReceiveHandle";
import { CryptoPublicStateHandle } from "../crypto-layer/state/CryptoPublicStateHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPrivateState, ICryptoPrivateState, ICryptoPrivateStateSerialized } from "./CryptoPrivateState";
import { CryptoPublicState } from "./CryptoPublicState";
import { CryptoStateType } from "./CryptoStateType";

@type("CryptoPrivateStateReceive")
export class CryptoPrivateStateReceive extends CryptoPrivateState {
    public override async toJSON(verbose = true): Promise<ICryptoPrivateStateSerialized> {
        const obj = await super.toJSON(verbose);
        obj["@type"] = "CryptoPrivateStateReceive";
        return obj;
    }

    /**
     * Converts this state to a CAL handle
     * @returns A CAL private state receive handle
     */
    public async toHandle(): Promise<CryptoPrivateStateReceiveHandle> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoPrivateStateReceiveHandle.from({
                nonce: this.nonce,
                counter: this.counter,
                algorithm: this.algorithm,
                id: this.id,
                stateType: CryptoStateType.Receive,
                secretKeyHandle: this.secretKey
            });
        }

        throw new CryptoError(
            CryptoErrorCode.CalUninitializedKey,
            "Cannot create handle: this state doesn't use a crypto-layer key handle"
        );
    }

    /**
     * Creates a state object from a CAL handle
     * @param handle The CAL handle
     * @returns A CryptoPrivateStateReceive instance
     */
    public static async fromHandle(handle: CryptoPrivateStateReceiveHandle): Promise<CryptoPrivateStateReceive> {
        return CryptoPrivateStateReceive.from({
            nonce: handle.nonce,
            counter: handle.counter,
            secretKey: handle.secretKeyHandle,
            algorithm: handle.algorithm,
            id: handle.id,
            stateType: handle.stateType
        });
    }

    public async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        CryptoValidation.checkCounter(cipher.counter);

        if (typeof cipher.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.StateWrongCounter, "Cipher counter is undefined");
        }

        let plaintext: CoreBuffer;

        if (omitCounterCheck) {
            // Skip counter check and just decrypt
            if (this.secretKey instanceof CryptoSecretKeyHandle) {
                // Using crypto-layer implementation
                plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                    cipher,
                    this.secretKey,
                    this.nonce
                );
            } else {
                // Using libsodium implementation
                plaintext = await CryptoEncryption.decryptWithCounter(
                    cipher,
                    this.secretKey,
                    this.nonce,
                    cipher.counter
                );
            }
        } else {
            // Verify counter before decrypting
            if (this.counter !== cipher.counter) {
                throw new CryptoError(
                    CryptoErrorCode.StateWrongOrder,
                    `The current message seems to be out of order. The in order number would be ${this.counter} and message is ${cipher.counter}.`
                );
            }

            if (this.secretKey instanceof CryptoSecretKeyHandle) {
                // Using crypto-layer implementation
                plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                    cipher,
                    this.secretKey,
                    this.nonce
                );
            } else {
                // Using libsodium implementation
                plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, this.counter);
            }

            // Increment counter after successful decryption
            const newCounter = this.counter + 1;
            this.setCounter(newCounter);
        }

        return plaintext;
    }

    /**
     * Creates a state from a nonce and secret key
     * @param nonce The nonce to use
     * @param secretKey The secret key or handle
     * @param counter Initial counter value
     * @returns A receive state or CAL handle
     */
    public static async fromNonce(
        nonce: CoreBuffer,
        secretKey: CoreBuffer | CryptoSecretKeyHandle,
        counter = 0
    ): Promise<CryptoPrivateStateReceive | CryptoPrivateStateReceiveHandle> {
        if (secretKey instanceof CryptoSecretKeyHandle) {
            // Create a handle-based state for CAL
            const receiveStateHandle = await CryptoPrivateStateReceiveHandle.from({
                nonce: nonce.clone(),
                counter,
                secretKeyHandle: secretKey,
                algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                stateType: CryptoStateType.Receive
            });
            return receiveStateHandle;
        }

        // Create a regular state for libsodium
        return CryptoPrivateStateReceive.from({
            nonce: nonce.clone(),
            counter,
            secretKey,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Receive
        });
    }

    /**
     * Creates a state from a public state
     * @param publicState The public state or handle
     * @param secretKey The secret key or handle
     * @param counter Initial counter value
     * @returns A receive state or CAL handle
     */
    public static async fromPublicState(
        publicState: CryptoPublicState | CryptoPublicStateHandle,
        secretKey: CoreBuffer | CryptoSecretKeyHandle,
        counter = 0
    ): Promise<CryptoPrivateStateReceive | CryptoPrivateStateReceiveHandle> {
        // If we have CAL handle types
        if (publicState instanceof CryptoPublicStateHandle && secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoPrivateStateReceiveHandle.from({
                nonce: publicState.nonce.clone(),
                counter,
                secretKeyHandle: secretKey,
                algorithm: publicState.algorithm,
                id: publicState.id,
                stateType: CryptoStateType.Receive
            });
        }

        // If it's a mix of types, get the correct properties
        const nonce = publicState.nonce.clone();
        const algorithm = publicState.algorithm;
        const id = publicState.id;

        // Create the appropriate state type
        if (secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoPrivateStateReceiveHandle.from({
                nonce,
                counter,
                secretKeyHandle: secretKey,
                algorithm,
                id,
                stateType: CryptoStateType.Receive
            });
        }

        // Create a regular state for libsodium
        return CryptoPrivateStateReceive.from({
            nonce,
            counter,
            secretKey,
            algorithm,
            id,
            stateType: CryptoStateType.Receive
        });
    }

    protected static override preFrom(value: any): any {
        value = super.preFrom(value);

        CryptoValidation.checkBufferAsStringOrBuffer(value.nonce, 0, 24, "nonce");
        if (!(value.secretKey instanceof CryptoSecretKeyHandle)) {
            CryptoValidation.checkSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        }

        if (value.stateType) {
            CryptoValidation.checkStateType(value.stateType);
        }

        return value;
    }

    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateReceive {
        return this.fromAny(obj);
    }

    public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateReceive {
        return this.fromAny(value);
    }
}
