import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPrivateState, ICryptoPrivateState, ICryptoPrivateStateSerialized } from "./CryptoPrivateState";
import { CryptoStateType } from "./CryptoStateType";

// Import crypto‑layer modules
import { CryptoEncryptionWithCryptoLayer } from "src/crypto-layer/encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "src/crypto-layer/encryption/CryptoSecretKeyHandle";

@type("CryptoPrivateStateTransmit")
export class CryptoPrivateStateTransmit extends CryptoPrivateState {
    public override toJSON(): ICryptoPrivateStateSerialized {
        const obj = super.toJSON();
        obj["@type"] = "CryptoPrivateStateTransmit";
        return obj;
    }

    public async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            // Delegate to the crypto‑layer implementation
            const cipher = await CryptoEncryptionWithCryptoLayer.encryptWithCounter(
                plaintext,
                this.secretKey,
                this.counter
            );
            this.setCounter(this.counter + 1);
            return cipher;
        }
        // Fallback to the libsodium implementation
        const cipher = await CryptoEncryption.encryptWithCounter(
            plaintext,
            this.secretKey,
            this.nonce,
            this.counter,
            this.algorithm
        );
        this.setCounter(this.counter + 1);
        return cipher;
    }

    public async decrypt(cipher: CryptoCipher): Promise<CoreBuffer> {
        // Although transmit state is usually used for encryption only,
        // we include decryption for symmetry.
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            CryptoValidation.checkCounter(cipher.counter);
            if (typeof cipher.counter === "undefined") {
                throw new CryptoError(CryptoErrorCode.StateWrongCounter);
            }
            if (this.counter !== cipher.counter) {
                throw new CryptoError(
                    CryptoErrorCode.StateWrongOrder,
                    `Expected counter ${this.counter} but got ${cipher.counter}.`
                );
            }
            const plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                cipher,
                this.secretKey,
                this.nonce
            );
            this.setCounter(this.counter + 1);
            return plaintext;
        }
        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.StateWrongCounter);
        }
        const plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, this.counter);
        this.setCounter(this.counter + 1);
        return plaintext;
    }

    public static generate(
        secretKey?: CoreBuffer,
        id?: string,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): CryptoPrivateStateTransmit {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);
        CryptoValidation.checkSecretKeyForAlgorithm(secretKey, algorithm);

        if (typeof secretKey === "undefined") {
            throw new CryptoError(CryptoErrorCode.StateWrongCounter);
        }

        const nonce = CryptoEncryption.createNonce(algorithm);
        const counter = 0;

        return this.from({ nonce, counter, secretKey, algorithm, id, stateType: CryptoStateType.Transmit });
    }

    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateTransmit {
        return this.fromAny(obj);
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

    public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateTransmit {
        return this.fromAny(value);
    }
}
