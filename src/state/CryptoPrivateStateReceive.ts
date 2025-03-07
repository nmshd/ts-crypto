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

/**
 * The original libsodium-based class, preserving your old implementation exactly.
 * Renamed to avoid collision with the new unified class.
 */
@type("CryptoPrivateStateReceiveWithLibsodium")
export class CryptoPrivateStateReceiveWithLibsodium extends CryptoPrivateState {
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        // Old code: keep your original @type, except rename it so it doesn't conflict:
        const obj = super.toJSON(verbose);
        // Now we set the old libsodium type
        obj["@type"] = verbose ? "CryptoPrivateStateReceiveWithLibsodium" : undefined;
        return obj;
    }

    /**
     * The original libsodium-based decrypt method (no changes).
     */
    public override async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        CryptoValidation.checkCounter(cipher.counter);
        if (typeof cipher.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.Unknown);
        }

        if (!omitCounterCheck && this.counter !== cipher.counter) {
            throw new CryptoError(
                CryptoErrorCode.StateWrongOrder,
                `Expected counter ${this.counter} but got ${cipher.counter}.`
            );
        }

        const plaintext: CoreBuffer = await CryptoEncryption.decryptWithCounter(
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
 * A new class that extends the old libsodium-based approach, adding
 * handle-based usage if a crypto-layer provider is initialized.
 */
@type("CryptoPrivateStateReceive")
export class CryptoPrivateStateReceive extends CryptoPrivateStateReceiveWithLibsodium {
    /**
     * Override the toJSON method to produce `@type: "CryptoPrivateStateReceive"`.
     * This ensures we can deserialize back into this class, not the old one.
     */
    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const obj = super.toJSON(false); // get the base structure
        obj["@type"] = verbose ? "CryptoPrivateStateReceive" : undefined;
        return obj;
    }

    /**
     * Overridden decrypt method. If we have a handle-based key and the provider is init,
     * delegate to the handle's logic. Otherwise, fallback to libsodium base.
     */
    public override async decrypt(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        // If the state is provider-initialized and the secretKey is actually a handle
        if (stateProviderInitialized && this.secretKey instanceof CryptoSecretKeyHandle) {
            // check counter
            CryptoValidation.checkCounter(cipher.counter);
            if (typeof cipher.counter === "undefined") {
                throw new CryptoError(CryptoErrorCode.Unknown);
            }

            // If omitCounterCheck is false, ensure counters align
            if (!omitCounterCheck && this.counter !== cipher.counter) {
                throw new CryptoError(
                    CryptoErrorCode.StateWrongOrder,
                    `Expected counter ${this.counter} but got ${cipher.counter}.`
                );
            }

            // Decrypt via handle-based approach
            const plaintext = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                cipher,
                this.secretKey,
                this.nonce
            );

            // increment if not omitting
            if (!omitCounterCheck) this.setCounter(this.counter + 1);
            return plaintext;
        }

        // otherwise libsodium fallback
        return await super.decrypt(cipher, omitCounterCheck);
    }

    /**
     * Overridden fromNonce. If the user calls it, they get the new class.
     */
    public static override fromNonce(nonce: CoreBuffer, secretKey: CoreBuffer, counter = 0): CryptoPrivateStateReceive {
        // return an instance of this class
        const base = super.fromNonce(nonce, secretKey, counter);
        return this.from(base);
    }

    /**
     * Overridden fromPublicState. If the user calls it, they get the new class.
     */
    public static override fromPublicState(
        publicState: CryptoPublicState,
        secretKey: CoreBuffer,
        counter = 0
    ): CryptoPrivateStateReceive {
        const base = super.fromPublicState(publicState, secretKey, counter);
        return this.from(base);
    }

    /**
     * Overridden from() so that if user calls CryptoPrivateStateReceive.from(...) we produce
     * an instance of this extended class, not the base libsodium class.
     */
    public static override from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateStateReceive {
        // parse as the base type, then create an instance of this class
        const base = super.fromAny(obj); // base is CryptoPrivateStateReceiveWithLibsodium
        // now convert to the extended class
        const extended = new CryptoPrivateStateReceive();
        // copy fields
        extended.id = base.id;
        extended.nonce = base.nonce;
        extended.counter = (base as any).counter;
        extended.secretKey = (base as any).secretKey;
        extended.algorithm = (base as any).algorithm;
        extended.stateType = (base as any).stateType;
        return extended;
    }

    // /**
    //  * Overridden fromJSON so it ends up in the extended class, not the base class.
    //  */
    // public static override fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateStateReceive {
    //     return this.from(value);
    // }
}
