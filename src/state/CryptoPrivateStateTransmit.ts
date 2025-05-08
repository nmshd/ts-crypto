import { type } from "@js-soft/ts-serval";
import { CryptoPrivateStateTransmitHandle } from "src/crypto-layer";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoEncryptionWithCryptoLayer } from "../crypto-layer/encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPrivateState, ICryptoPrivateState, ICryptoPrivateStateSerialized } from "./CryptoPrivateState";
import { CryptoStateType } from "./CryptoStateType";

@type("CryptoPrivateStateTransmitWithLibsodium")
export class CryptoPrivateStateTransmitWithLibsodium extends CryptoPrivateState {
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const obj = super.toJSON(verbose);
        obj["@type"] = verbose ? "CryptoPrivateStateTransmitWithLibsodium" : undefined;
        return obj;
    }

    public override async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
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

    public override async decrypt(cipher: CryptoCipher): Promise<CoreBuffer> {
        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") throw new CryptoError(CryptoErrorCode.StateWrongCounter);

        const plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, cipher.counter);
        return plaintext;
    }

    public static generate(
        secretKey?: CoreBuffer,
        id?: string,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): CryptoPrivateStateTransmitWithLibsodium {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);
        CryptoValidation.checkSecretKeyForAlgorithm(secretKey, algorithm);

        if (typeof secretKey === "undefined") throw new CryptoError(CryptoErrorCode.StateWrongCounter);

        const nonce = CryptoEncryption.createNonce(algorithm);
        const counter = 0;

        return this.from({ nonce, counter, secretKey, algorithm, id, stateType: CryptoStateType.Transmit });
    }

    public static override from(
        obj: CryptoPrivateState | ICryptoPrivateState
    ): CryptoPrivateStateTransmitWithLibsodium {
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

    public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateTransmitWithLibsodium {
        return this.fromAny(value);
    }
}

@type("CryptoPrivateStateTransmit")
export class CryptoPrivateStateTransmit extends CryptoPrivateStateTransmitWithLibsodium {
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const obj = super.toJSON(false);
        obj["@type"] = verbose ? "CryptoPrivateStateTransmit" : undefined;
        return obj;
    }

    public override async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            const cipher = await CryptoEncryptionWithCryptoLayer.encrypt(
                plaintext,
                await CryptoSecretKeyHandle.from(this.secretKey)
            );
            this.setCounter(this.counter + 1);
            return cipher;
        }
        return await super.encrypt(plaintext);
    }

    public override async decrypt(cipher: CryptoCipher): Promise<CoreBuffer> {
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

            const plaintext = await CryptoEncryptionWithCryptoLayer.decrypt(
                cipher,
                await CryptoSecretKeyHandle.from(this.secretKey),
                this.nonce
            );
            this.setCounter(this.counter + 1);
            return plaintext;
        }
        return await super.decrypt(cipher);
    }

    public static override generate(
        secretKey?: CoreBuffer,
        id?: string,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): CryptoPrivateStateTransmit {
        const base = super.generate(secretKey, id, algorithm);
        return this.from(base);
    }

    public static async generateHandle(
        secretKey: CryptoSecretKeyHandle,
        id?: string,
        algorithm?: CryptoEncryptionAlgorithm
    ): Promise<CryptoPrivateStateTransmitHandle> {
        return await CryptoPrivateStateTransmitHandle.generate(secretKey, id, algorithm);
    }

    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateTransmit {
        const base = super.fromAny(obj);
        return this.fromAny(base);
    }

    // public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateTransmit {
    //     return this.from(value);
    // }
}
