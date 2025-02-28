import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../CoreBuffer";
import { ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { CryptoExchangeWithCryptoLayer as CryptoExchangeLayer } from "../crypto-layer/exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../crypto-layer/exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePrivateKeyHandle } from "../crypto-layer/exchange/CryptoExchangePrivateKeyHandle";
import { CryptoExchangePublicKeyHandle } from "../crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoExchangeAlgorithmUtil } from "./CryptoExchangeAlgorithmUtil";
import { CryptoExchangeKeypair } from "./CryptoExchangeKeypair";
import { CryptoExchangePrivateKey } from "./CryptoExchangePrivateKey";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeSecrets } from "./CryptoExchangeSecrets";

export const enum CryptoExchangeAlgorithm {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P256 = 1,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P521 = 2,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_X25519 = 3
}

// Abstract base class that ensures type compatibility
abstract class CryptoExchangeBase {
    public static async generateKeypair(
        algorithm: CryptoExchangeAlgorithm,
        providerIdent?: ProviderIdentifier,
        spec?: KeyPairSpec
    ): Promise<CryptoExchangeKeypair | CryptoExchangeKeypairHandle> {
        throw new Error("Abstract method");
    }

    public static async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        templatorPublicKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoExchangeSecrets> {
        throw new Error("Abstract method");
    }

    public static async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        requestorPublicKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoExchangeSecrets> {
        throw new Error("Abstract method");
    }
}

export class CryptoExchangeWithLibsodium extends CryptoExchangeBase {
    /**
     * Generates a keypair for the specified key exchange algorithm
     *
     * @param algorithm The [[CryptoExchangeAlgorithm]] for which a keypair should be generated. Defaults to ECDH_X25519
     * @returns A Promise resolving into a [[CryptoExchangeKeypair]] object
     */
    public static override async generateKeypair(
        algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_X25519
    ): Promise<CryptoExchangeKeypair> {
        let privateKeyBuffer;
        let publicKeyBuffer;

        switch (algorithm as number) {
            case CryptoExchangeAlgorithm.ECDH_X25519:
                let pair;
                try {
                    pair = (await SodiumWrapper.ready()).crypto_kx_keypair();
                } catch (e: any) {
                    throw new CryptoError(CryptoErrorCode.ExchangeKeyGeneration, `${e}`);
                }
                privateKeyBuffer = pair.privateKey;
                publicKeyBuffer = pair.publicKey;
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }

        const privateKey = CryptoExchangePrivateKey.from({ algorithm, privateKey: CoreBuffer.from(privateKeyBuffer) });
        const publicKey = CryptoExchangePublicKey.from({ algorithm, publicKey: CoreBuffer.from(publicKeyBuffer) });
        const keypair = CryptoExchangeKeypair.from({ publicKey, privateKey });

        return keypair;
    }

    /**
     * Derives session keys from the given private exchange keypair and the given public
     * exchange keypair of another party. Please ensure, that the server/sender/from entity
     * calls the deriveRequestor method, whereas the counterparty (client/recipient/to entity)
     * needs to call the deriveTemplator method, in order to derive the working keys.
     *
     * The method derives two separate secret keys: One for transmission (transmissionKey) and
     * one for receiving (receivingKey). Please only use the respective keys for their purpose.
     *
     * @param requestorKeypair The [[CryptoExchangeKeypair]] of the sending side
     * @param templatorPublicKey The [[CryptoExchangePublicKey]] of the receiving side
     * @param algorithm The [[CryptoEncryptionAlgorithm]] algorithm for which the secret keys should
     * be generated.
     * @returns A Promise resolving into a [[CryptoExchangeSecrets]] object, containing the shared keys
     * for transmission and receiving.
     */
    public static override async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair,
        templatorPublicKey: CryptoExchangePublicKey,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        let sharedKey;
        try {
            sharedKey = (await SodiumWrapper.ready()).crypto_kx_server_session_keys(
                requestorKeypair.publicKey.publicKey.buffer,
                requestorKeypair.privateKey.privateKey.buffer,
                templatorPublicKey.publicKey.buffer
            );
        } catch (e: any) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }

        const secrets = CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
        return secrets;
    }

    /**
     * Derives session keys from the given private exchange keypair and the given public
     * exchange keypair of another party. Please ensure, that the server/sender/from entity
     * calls the deriveRequestor method, whereas the counterparty (client/recipient/to entity)
     * needs to call the deriveTemplator method, in order to derive the working keys.
     *
     * The method derives two separate secret keys: One for transmission (transmissionKey) and
     * one for receiving (receivingKey). Please only use the respective keys for their purpose.
     *
     * @param templatorKeypair The [[CryptoExchangeKeypair]] of the receiving side
     * @param requestorPublicKey The [[CryptoExchangePublicKey]] of the sending side
     * @param algorithm The [[CryptoEncryptionAlgorithm]] algorithm for which the secret keys should
     * be generated.
     * @returns A Promise resolving into a [[CryptoExchangeSecrets]] object, containing the shared keys
     * for transmission and receiving.
     */
    public static override async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair,
        requestorPublicKey: CryptoExchangePublicKey,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        let sharedKey;
        try {
            sharedKey = (await SodiumWrapper.ready()).crypto_kx_client_session_keys(
                templatorKeypair.publicKey.publicKey.buffer,
                templatorKeypair.privateKey.privateKey.buffer,
                requestorPublicKey.publicKey.buffer
            );
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }

        const secrets = CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
        return secrets;
    }
}

// Add a flag to check if crypto-layer provider is initialized
let providerInitialized = false;

// Function to initialize crypto-layer for exchange operations
export function initCryptoExchange(providerIdent: ProviderIdentifier): void {
    if (providerIdent) {
        providerInitialized = true;
    }
}

export class CryptoExchange extends CryptoExchangeBase {
    /**
     * Asynchronously converts a private key handle for key exchange into its corresponding public key handle.
     *
     * @param privateKey - The CryptoExchangePrivateKeyHandle to convert.
     * @returns A Promise that resolves to a CryptoExchangePublicKeyHandle.
     */
    public static async privateKeyHandleToPublicKey(
        privateKey: CryptoExchangePrivateKeyHandle
    ): Promise<CryptoExchangePublicKeyHandle> {
        return await CryptoExchangeLayer.privateKeyToPublicKey(privateKey);
    }

    /**
     * Asynchronously generates a key pair handle for cryptographic key exchange using the crypto layer.
     *
     * @param providerIdent - Identifier for the crypto provider to be used for key generation.
     * @param spec - Specification for the key pair to be generated, including algorithm and security parameters.
     * @returns A Promise that resolves to a CryptoExchangeKeypairHandle containing the generated key pair handles.
     */
    public static async generateKeypairHandle(
        providerIdent: ProviderIdentifier,
        spec: KeyPairSpec
    ): Promise<CryptoExchangeKeypairHandle> {
        return await CryptoExchangeLayer.generateKeypair(providerIdent, spec);
    }

    /**
     * Generates a keypair for the specified key exchange algorithm, using either libsodium or crypto-layer
     * based on provider initialization.
     *
     * @param algorithm The algorithm for which a keypair should be generated. Defaults to ECDH_X25519
     * @param providerIdent Optional provider identifier for crypto-layer
     * @param spec Optional key specification for crypto-layer
     * @returns A Promise resolving to either a traditional keypair or a keypair handle
     */
    public static override async generateKeypair(
        algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_X25519,
        providerIdent?: ProviderIdentifier,
        spec?: KeyPairSpec
    ): Promise<CryptoExchangeKeypair | CryptoExchangeKeypairHandle> {
        if (providerInitialized && providerIdent) {
            if (!spec) {
                spec = {
                    // create default spec if not provided
                    asym_spec: CryptoExchangeAlgorithmUtil.toCalAsymSpec(algorithm),
                    cipher: "AesGcm256", // default cipher
                    signing_hash: "Sha2_512", // default hash
                    ephemeral: false,
                    non_exportable: false
                };
            }
            return await CryptoExchangeLayer.generateKeypair(providerIdent, spec);
        }
        return await CryptoExchangeWithLibsodium.generateKeypair(algorithm);
    }

    /**
     * Derives shared secrets for key exchange in the 'requestor' role using crypto-layer.
     * This method properly delegates to the CAL implementation.
     *
     * @param requestorKeypair - The keypair handle of the requestor
     * @param templatorPublicKey - The public key handle of the templator
     * @param algorithm - The encryption algorithm to use for the derived keys
     * @returns A Promise resolving to the derived exchange secrets
     */
    public static async deriveRequestorWithHandles(
        requestorKeypair: CryptoExchangeKeypairHandle,
        templatorPublicKey: CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        // Properly delegate to the CAL implementation
        return await CryptoExchangeLayer.deriveRequestor(requestorKeypair, templatorPublicKey, algorithm);
    }

    /**
     * Derives shared secrets for key exchange in the 'requestor' role.
     * This method handles both traditional keypair objects and crypto-layer handle objects.
     *
     * @param requestorKeypair - The keypair of the requestor (can be either traditional or handle-based)
     * @param templatorPublicKey - The public key of the templator (can be either traditional or handle-based)
     * @param algorithm - The encryption algorithm to use for the derived keys
     * @returns A Promise resolving to the derived exchange secrets
     */
    public static override async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        templatorPublicKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        if (
            providerInitialized &&
            requestorKeypair instanceof CryptoExchangeKeypairHandle &&
            templatorPublicKey instanceof CryptoExchangePublicKeyHandle
        ) {
            return await this.deriveRequestorWithHandles(requestorKeypair, templatorPublicKey, algorithm);
        }

        // If either input is not a handle object or provider not initialized, use the libsodium implementation
        if (
            !(requestorKeypair instanceof CryptoExchangeKeypairHandle) &&
            !(templatorPublicKey instanceof CryptoExchangePublicKeyHandle)
        ) {
            return await CryptoExchangeWithLibsodium.deriveRequestor(
                requestorKeypair as CryptoExchangeKeypair,
                templatorPublicKey as CryptoExchangePublicKey,
                algorithm
            );
        }

        // If we get here, there's a mismatch in types
        throw new CryptoError(
            CryptoErrorCode.ExchangeWrongAlgorithm,
            "Mismatch in keypair types: both must be either traditional or handle-based"
        );
    }

    /**
     * Derives shared secrets for key exchange in the 'templator' role using crypto-layer.
     * This method properly delegates to the CAL implementation.
     *
     * @param templatorKeypair - The keypair handle of the templator
     * @param requestorPublicKey - The public key handle of the requestor
     * @param algorithm - The encryption algorithm to use for the derived keys
     * @returns A Promise resolving to the derived exchange secrets
     */
    public static async deriveTemplatorWithHandles(
        templatorKeypair: CryptoExchangeKeypairHandle,
        requestorPublicKey: CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        // Properly delegate to the CAL implementation
        return await CryptoExchangeLayer.deriveTemplator(templatorKeypair, requestorPublicKey, algorithm);
    }

    /**
     * Derives shared secrets for key exchange in the 'templator' role.
     * This method handles both traditional keypair objects and crypto-layer handle objects.
     *
     * @param templatorKeypair - The keypair of the templator (can be either traditional or handle-based)
     * @param requestorPublicKey - The public key of the requestor (can be either traditional or handle-based)
     * @param algorithm - The encryption algorithm to use for the derived keys
     * @returns A Promise resolving to the derived exchange secrets
     */
    public static override async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        requestorPublicKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        if (
            providerInitialized &&
            templatorKeypair instanceof CryptoExchangeKeypairHandle &&
            requestorPublicKey instanceof CryptoExchangePublicKeyHandle
        ) {
            return await this.deriveTemplatorWithHandles(templatorKeypair, requestorPublicKey, algorithm);
        }

        // If either input is not a handle object or provider not initialized, use the libsodium implementation
        if (
            !(templatorKeypair instanceof CryptoExchangeKeypairHandle) &&
            !(requestorPublicKey instanceof CryptoExchangePublicKeyHandle)
        ) {
            return await CryptoExchangeWithLibsodium.deriveTemplator(
                templatorKeypair as CryptoExchangeKeypair,
                requestorPublicKey as CryptoExchangePublicKey,
                algorithm
            );
        }

        // If we get here, there's a mismatch in types
        throw new CryptoError(
            CryptoErrorCode.ExchangeWrongAlgorithm,
            "Mismatch in keypair types: both must be either traditional or handle-based"
        );
    }
}
