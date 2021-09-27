import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../CoreBuffer";
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
    public constructor(
        nonce: CoreBuffer,
        counter: number,
        secretKey: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm,
        id?: string
    ) {
        super(nonce, counter, secretKey, algorithm, CryptoStateType.Receive, id);
    }

    public toJSON(): ICryptoPrivateStateSerialized {
        const obj = super.toJSON();
        obj["@type"] = "CryptoPrivateStateReceive";
        return obj;
    }

    public async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        let plaintext;

        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") throw new CryptoError(CryptoErrorCode.Unknown);

        if (omitCounterCheck) {
            plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, cipher.counter);
        } else {
            if (this.counter !== cipher.counter) {
                throw new CryptoError(
                    CryptoErrorCode.StateWrongOrder,
                    `The current message seems to be out of order. The in order number would be ${this.counter} and message is ${cipher.counter}.`
                );
            }
            plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, this.counter);
            const newCounter = this.counter + 1;
            this.setCounter(newCounter);
        }

        return plaintext;
    }

    public static fromNonce(nonce: CoreBuffer, secretKey: CoreBuffer, counter = 0): CryptoPrivateStateReceive {
        return new CryptoPrivateStateReceive(
            nonce.clone(),
            counter,
            secretKey,
            CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
        );
    }

    public static fromPublicState(
        publicState: CryptoPublicState,
        secretKey: CoreBuffer,
        counter = 0
    ): Promise<CryptoPrivateStateReceive> {
        return Promise.resolve(
            new CryptoPrivateStateReceive(
                publicState.nonce.clone(),
                counter,
                secretKey,
                publicState.algorithm,
                publicState.id
            )
        );
    }

    public static from(obj: CryptoPrivateState | ICryptoPrivateState): Promise<CryptoPrivateStateReceive> {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!obj.secretKey) {
            throw new CryptoError(CryptoErrorCode.StateWrongSecretKey, "No secretKey set.");
        }
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!obj.nonce) {
            throw new CryptoError(CryptoErrorCode.StateWrongNonce, "No nonce set.");
        }
        if (typeof obj.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.StateWrongCounter, "No counter.");
        }

        if (obj.stateType !== CryptoStateType.Receive) {
            throw new CryptoError(CryptoErrorCode.StateWrongType, "The given object has a wrong state type.");
        }

        return Promise.resolve(
            new CryptoPrivateStateReceive(
                CoreBuffer.from(obj.nonce),
                obj.counter,
                CoreBuffer.from(obj.secretKey),
                obj.algorithm,
                obj.id
            )
        );
    }

    public static fromJSON(value: ICryptoPrivateStateSerialized): Promise<CryptoPrivateStateReceive> {
        CryptoValidation.checkEncryptionAlgorithm(value.alg);
        CryptoValidation.checkCounter(value.cnt);
        CryptoValidation.checkSerializedBuffer(value.nnc, 0, 24, "nnc");
        CryptoValidation.checkSerializedSecretKeyForAlgorithm(value.key, value.alg as CryptoEncryptionAlgorithm);
        if (value.typ) {
            CryptoValidation.checkStateType(value.typ);
        }
        const nonceBuffer = CoreBuffer.fromBase64URL(value.nnc);
        const secretKeyBuffer = CoreBuffer.fromBase64URL(value.key);
        return Promise.resolve(
            new CryptoPrivateStateReceive(
                nonceBuffer,
                value.cnt,
                secretKeyBuffer,
                value.alg as CryptoEncryptionAlgorithm,
                value.id
            )
        );
    }

    public static async deserialize(value: string): Promise<CryptoPrivateStateReceive> {
        return await this.fromJSON(JSON.parse(value));
    }
}
