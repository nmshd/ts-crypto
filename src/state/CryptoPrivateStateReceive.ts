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

// Import crypto‑layer modules
import { ProviderIdentifier, getProvider } from "src/crypto-layer/CryptoLayerProviders";
import { CryptoEncryptionWithCryptoLayer } from "src/crypto-layer/encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "src/crypto-layer/encryption/CryptoSecretKeyHandle";

/**
 * Flag indicating whether a crypto‑layer provider for state operations is initialized.
 */
let stateProviderInitialized = false;

/**
 * Initializes the crypto state subsystem to use the crypto layer.
 *
 * @param providerIdent - The provider identifier.
 */
export function initCryptoState(providerIdent: ProviderIdentifier): void {
    if (getProvider(providerIdent)) {
        stateProviderInitialized = true;
    }
}

@type("CryptoPrivateStateReceive")
export class CryptoPrivateStateReceive extends CryptoPrivateState {
    public override toJSON(): ICryptoPrivateStateSerialized {
        const obj = super.toJSON();
        obj["@type"] = "CryptoPrivateStateReceive";
        return obj;
    }

    public async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        if (stateProviderInitialized && this.secretKey instanceof CryptoSecretKeyHandle) {
            CryptoValidation.checkCounter(cipher.counter);
            if (typeof cipher.counter === "undefined") {
                throw new CryptoError(CryptoErrorCode.Unknown);
            }
            let plaintext: CoreBuffer;
            if (omitCounterCheck) {
                plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                    cipher,
                    this.secretKey,
                    this.nonce
                );
            } else {
                if (this.counter !== cipher.counter) {
                    throw new CryptoError(
                        CryptoErrorCode.StateWrongOrder,
                        `Expected counter ${this.counter} but got ${cipher.counter}.`
                    );
                }
                plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                    cipher,
                    this.secretKey,
                    this.nonce
                );
                this.setCounter(this.counter + 1);
            }
            return plaintext;
        }
        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.Unknown);
        }
        let plaintext: CoreBuffer;
        if (omitCounterCheck) {
            plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, cipher.counter);
        } else {
            if (this.counter !== cipher.counter) {
                throw new CryptoError(
                    CryptoErrorCode.StateWrongOrder,
                    `Expected counter ${this.counter} but got ${cipher.counter}.`
                );
            }
            plaintext = await CryptoEncryption.decryptWithCounter(cipher, this.secretKey, this.nonce, this.counter);
            this.setCounter(this.counter + 1);
        }
        return plaintext;
    }

    public static fromNonce(nonce: CoreBuffer, secretKey: CoreBuffer, counter = 0): CryptoPrivateStateReceive {
        return CryptoPrivateStateReceive.from({
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
    ): CryptoPrivateStateReceive {
        return CryptoPrivateStateReceive.from({
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

    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateReceive {
        return this.fromAny(obj);
    }

    public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateReceive {
        return this.fromAny(value);
    }
}
