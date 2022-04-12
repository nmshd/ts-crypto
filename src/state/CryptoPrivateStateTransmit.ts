import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPrivateState, ICryptoPrivateState, ICryptoPrivateStateSerialized } from "./CryptoPrivateState";
import { CryptoStateType } from "./CryptoStateType";

@type("CryptoPrivateStateTransmit")
export class CryptoPrivateStateTransmit extends CryptoPrivateState {
    public override toJSON(): ICryptoPrivateStateSerialized {
        const obj = super.toJSON();
        obj["@type"] = "CryptoPrivateStateTransmit";
        return obj;
    }

    public async encrypt(plaintext: CoreBuffer): Promise<CryptoCipher> {
        const cipher = await CryptoEncryption.encryptWithCounter(plaintext, this.secretKey, this.nonce, this.counter);
        const newCounter = this.counter + 1;
        this.setCounter(newCounter);
        return cipher;
    }

    public async decrypt(cipher: CryptoCipher): Promise<CoreBuffer> {
        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") throw new CryptoError(CryptoErrorCode.StateWrongCounter);

        const plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, cipher.counter);

        return plaintext;
    }

    public static generate(
        secretKey?: CoreBuffer,
        id?: string,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): CryptoPrivateStateTransmit {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);
        CryptoValidation.checkSecretKeyForAlgorithm(secretKey, algorithm);

        if (typeof secretKey === "undefined") throw new CryptoError(CryptoErrorCode.StateWrongCounter);

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
