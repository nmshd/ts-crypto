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
    public constructor(
        nonce: CoreBuffer,
        counter: number,
        secretKey: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
        id?: string
    ) {
        super(nonce, counter, secretKey, algorithm, CryptoStateType.Transmit, id);
    }

    public toJSON(): ICryptoPrivateStateSerialized {
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

        return new CryptoPrivateStateTransmit(nonce, counter, secretKey, algorithm, id);
    }

    public static from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateTransmit {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!obj.secretKey) {
            throw new CryptoError(CryptoErrorCode.StateWrongSecretKey, "No secretKey property set.");
        }
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!obj.nonce) {
            throw new CryptoError(CryptoErrorCode.StateWrongNonce, "No nonce nor counter property set.");
        }
        if (typeof obj.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.StateWrongCounter, "Wrong counter.");
        }

        if (obj.stateType !== CryptoStateType.Transmit) {
            throw new CryptoError(CryptoErrorCode.StateWrongType, "The given object has a wrong state type.");
        }

        return new CryptoPrivateStateTransmit(
            CoreBuffer.from(obj.nonce),
            obj.counter,
            CoreBuffer.from(obj.secretKey),
            obj.algorithm,
            obj.id
        );
    }

    public static fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateTransmit {
        CryptoValidation.checkEncryptionAlgorithm(value.alg);
        CryptoValidation.checkCounter(value.cnt);
        CryptoValidation.checkSerializedBuffer(value.nnc, 0, 24, "nonce");
        CryptoValidation.checkSerializedSecretKeyForAlgorithm(value.key, value.alg as CryptoEncryptionAlgorithm);
        if (value.typ) {
            CryptoValidation.checkStateType(value.typ);
        }
        const nonceBuffer = CoreBuffer.fromBase64URL(value.nnc);
        const secretKeyBuffer = CoreBuffer.fromBase64URL(value.key);
        return new CryptoPrivateStateTransmit(
            nonceBuffer,
            value.cnt,
            secretKeyBuffer,
            value.alg as CryptoEncryptionAlgorithm,
            value.id
        );
    }

    public static deserialize(value: string): CryptoPrivateStateTransmit {
        return this.fromJSON(JSON.parse(value));
    }
}
