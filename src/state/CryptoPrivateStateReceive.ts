import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoEncryptionWithCryptoLayer } from "../crypto-layer/encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPrivateState, ICryptoPrivateState, ICryptoPrivateStateSerialized } from "./CryptoPrivateState";
import { CryptoPublicState } from "./CryptoPublicState";
import { CryptoStateType } from "./CryptoStateType";

/**
 * Original receive-only class using libsodium-based cryptography.
 * This class offers basic functionality for decrypting content with a persistent counter.
 */
@type("CryptoPrivateStateReceiveWithLibsodium")
export class CryptoPrivateStateReceiveWithLibsodium extends CryptoPrivateState {
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const obj = super.toJSON(verbose);
        obj["@type"] = verbose ? "CryptoPrivateStateReceiveWithLibsodium" : undefined;
        return obj;
    }

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
            this.secretKey,
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
        secretKey: CoreBuffer,
        counter = 0
    ): CryptoPrivateStateReceiveWithLibsodium {
        return this.from({
            nonce: nonce.clone(),
            counter,
            secretKey,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Receive
        });
    }

    public static fromPublicState(
        publicState: CryptoPublicState,
        secretKey: CoreBuffer,
        counter = 0
    ): CryptoPrivateStateReceiveWithLibsodium {
        return this.from({
            nonce: publicState.nonce.clone(),
            counter,
            secretKey,
            algorithm: publicState.algorithm,
            id: publicState.id,
            stateType: CryptoStateType.Receive
        });
    }

    protected static override preFrom(value: any): any {
        value = super.preFrom(value);
        CryptoValidation.checkBufferAsStringOrBuffer(value.nonce, 0, 24, "nonce");
        CryptoValidation.checkSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        if (value.stateType) {
            CryptoValidation.checkStateType(value.stateType);
        }
        return value;
    }

    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateReceiveWithLibsodium {
        return this.fromAny(obj);
    }

    public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateReceiveWithLibsodium {
        return this.fromAny(value);
    }
}

/**
 * Extended receive-only class that supports both handle-based and libsodium-based decryption.
 * If a handle-based provider is initialized and a handle key is present, this class delegates
 * decryption to the cryptographic provider. Otherwise, it falls back to libsodium logic.
 */
@type("CryptoPrivateStateReceive")
export class CryptoPrivateStateReceive extends CryptoPrivateStateReceiveWithLibsodium {
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const obj = super.toJSON(false);
        obj["@type"] = verbose ? "CryptoPrivateStateReceive" : undefined;
        return obj;
    }

    /**
     * Decrypts a cipher using the cryptographic handle if available and initialized;
     * otherwise, uses libsodium-based decryption. Maintains and checks the counter to ensure
     * proper message order, unless `omitCounterCheck` is true.
     */
    public override async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            const plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                cipher,
                this.secretKey,
                this.nonce
            );

            if (!omitCounterCheck) {
                if (typeof cipher.counter === "undefined") {
                    throw new CryptoError(CryptoErrorCode.Unknown, "Cipher is missing a counter.");
                }
                if (this.counter !== cipher.counter) {
                    throw new CryptoError(
                        CryptoErrorCode.StateWrongOrder,
                        `Expected counter ${this.counter} but got ${cipher.counter}.`
                    );
                }
                this.setCounter(this.counter + 1);
            }
            return plaintext;
        }

        return await super.decrypt(cipher, omitCounterCheck);
    }

    public static override fromNonce(nonce: CoreBuffer, secretKey: CoreBuffer, counter = 0): CryptoPrivateStateReceive {
        const base = super.fromNonce(nonce, secretKey, counter);
        return this.from(base);
    }

    public static override fromPublicState(
        publicState: CryptoPublicState,
        secretKey: CoreBuffer,
        counter = 0
    ): CryptoPrivateStateReceive {
        const base = super.fromPublicState(publicState, secretKey, counter);
        return this.from(base);
    }

    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateReceive {
        const base = super.fromAny(obj); // parent parses into CryptoPrivateStateReceiveWithLibsodium

        const extended = new CryptoPrivateStateReceive();
        extended.id = base.id;
        extended.nonce = base.nonce;
        extended.counter = base.counter;
        extended.secretKey = base.secretKey;
        extended.algorithm = base.algorithm;
        extended.stateType = base.stateType;

        return extended;
    }
}
