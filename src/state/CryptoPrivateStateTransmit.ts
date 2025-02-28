import { type } from "@js-soft/ts-serval";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../CoreBuffer";
import { getProvider, ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { DEFAULT_KEY_PAIR_SPEC } from "../crypto-layer/CryptoLayerUtils";
import { CryptoEncryptionWithCryptoLayer } from "../crypto-layer/encryption/CryptoEncryptionWithCryptoLayer";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoPrivateStateTransmitHandle } from "../crypto-layer/state/CryptoPrivateStateTransmitHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoEncryptionAlgorithmUtil } from "../encryption/CryptoEncryptionAlgorithmUtil";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoHashAlgorithmUtil } from "../hash/CryptoHashAlgorithmUtil";
import { CryptoPrivateState, ICryptoPrivateState, ICryptoPrivateStateSerialized } from "./CryptoPrivateState";
import { CryptoStateType } from "./CryptoStateType";

@type("CryptoPrivateStateTransmit")
export class CryptoPrivateStateTransmit extends CryptoPrivateState {
    public override async toJSON(verbose = true): Promise<ICryptoPrivateStateSerialized> {
        const obj = await super.toJSON(verbose);
        obj["@type"] = "CryptoPrivateStateTransmit";
        return obj;
    }

    public async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        let cipher: CryptoCipher;

        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            // Using crypto-layer implementation
            cipher = await CryptoEncryptionWithCryptoLayer.encryptWithCounter(
                plaintext,
                this.secretKey,
                this.nonce,
                this.counter
            );
        } else {
            // Using libsodium implementation
            cipher = await CryptoEncryption.encryptWithCounter(plaintext, this.secretKey, this.nonce, this.counter);
        }

        const newCounter = this.counter + 1;
        this.setCounter(newCounter);
        return cipher;
    }

    public async decrypt(cipher: CryptoCipher): Promise<CoreBuffer> {
        CryptoValidation.checkCounter(cipher.counter);

        if (typeof cipher.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.StateWrongCounter, "Cipher counter is undefined");
        }

        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            // Using crypto-layer implementation
            return await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                cipher,
                this.secretKey,
                this.nonce,
                cipher.counter
            );
        }

        // Using libsodium implementation
        return await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, cipher.counter);
    }

    /**
     * Converts this state to a CAL handle
     * @returns A CAL private state transmit handle
     */
    public async toHandle(): Promise<CryptoPrivateStateTransmitHandle> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoPrivateStateTransmitHandle.from({
                nonce: this.nonce,
                counter: this.counter,
                algorithm: this.algorithm,
                id: this.id,
                stateType: CryptoStateType.Transmit,
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
     * @returns A CryptoPrivateStateTransmit instance
     */
    public static async fromHandle(handle: CryptoPrivateStateTransmitHandle): Promise<CryptoPrivateStateTransmit> {
        return CryptoPrivateStateTransmit.from({
            nonce: handle.nonce,
            counter: handle.counter,
            secretKey: handle.secretKeyHandle,
            algorithm: handle.algorithm,
            id: handle.id,
            stateType: handle.stateType
        });
    }

    /**
     * Generates a new transmit state
     * @param secretKey Optional secret key or key handle
     * @param id Optional ID
     * @param algorithm Encryption algorithm to use
     * @param providerIdent Optional provider identifier for CAL
     * @param hashAlgorithm Hash algorithm to use
     * @returns A transmit state or CAL handle
     */
    public static async generate(
        secretKey?: CoreBuffer | CryptoSecretKeyHandle,
        id?: string,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
        providerIdent?: ProviderIdentifier,
        hashAlgorithm: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA512
    ): Promise<CryptoPrivateStateTransmit | CryptoPrivateStateTransmitHandle> {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);
        const nonce = CryptoEncryption.createNonce(algorithm);
        const counter = 0;

        // If we have a provider and are using CAL
        if (providerIdent && getProvider(providerIdent)) {
            if (!secretKey) {
                // Generate a new secret key if none provided
                const keySpec: KeySpec = {
                    ...DEFAULT_KEY_PAIR_SPEC,
                    cipher: CryptoEncryptionAlgorithmUtil.toCalCipher(algorithm),
                    signing_hash: CryptoHashAlgorithmUtil.toCalHash(hashAlgorithm)
                };

                const secretKeyHandle = await CryptoEncryptionWithCryptoLayer.generateKey(providerIdent, keySpec);
                const transmitStateHandle = await CryptoPrivateStateTransmitHandle.from({
                    nonce,
                    counter,
                    algorithm,
                    id,
                    stateType: CryptoStateType.Transmit,
                    secretKeyHandle
                });
                return transmitStateHandle;
            } else if (secretKey instanceof CryptoSecretKeyHandle) {
                // Use the provided handle
                const transmitStateHandle = await CryptoPrivateStateTransmitHandle.from({
                    nonce,
                    counter,
                    algorithm,
                    id,
                    stateType: CryptoStateType.Transmit,
                    secretKeyHandle: secretKey
                });
                return transmitStateHandle;
            } else {
                throw new CryptoError(
                    CryptoErrorCode.StateWrongType,
                    "If you provide a provider, you also have to provide a secretKeyHandle or no secretKey at all."
                );
            }
        }

        // Using libsodium implementation
        if (!secretKey) {
            throw new CryptoError(
                CryptoErrorCode.StateWrongSecretKey,
                "secretKey must be provided for libsodium implementation"
            );
        }

        if (secretKey instanceof CryptoSecretKeyHandle) {
            throw new CryptoError(
                CryptoErrorCode.StateWrongSecretKey,
                "Cannot use CryptoSecretKeyHandle without a provider identifier"
            );
        }

        CryptoValidation.checkSecretKeyForAlgorithm(secretKey, algorithm);

        return this.from({
            nonce,
            counter,
            secretKey,
            algorithm,
            id,
            stateType: CryptoStateType.Transmit
        });
    }

    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateTransmit {
        return this.fromAny(obj);
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

    public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateTransmit {
        return this.fromAny(value);
    }
}
