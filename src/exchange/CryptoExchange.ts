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

export class CryptoExchangeWithLibsodium {
    // No longer extends an abstract class
    /**
     * Generates a keypair for the specified key exchange algorithm
     */
    public static async generateKeypair(
        // Removed override
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
     * exchange keypair of another party.
     */
    public static async deriveRequestor(
        // Removed override
        requestorKeypair: CryptoExchangeKeypair, // No handles here
        templatorPublicKey: CryptoExchangePublicKey, // No handles here
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
     * exchange keypair of another party.
     */
    public static async deriveTemplator(
        // Removed override
        templatorKeypair: CryptoExchangeKeypair, // No handles here
        requestorPublicKey: CryptoExchangePublicKey, // No handles here
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

export class CryptoExchange extends CryptoExchangeWithLibsodium {
    // Extends CryptoExchangeWithLibsodium
    /**
     * Asynchronously converts a private key handle for key exchange into its corresponding public key handle.
     */
    public static async privateKeyHandleToPublicKey(
        privateKey: CryptoExchangePrivateKeyHandle
    ): Promise<CryptoExchangePublicKeyHandle> {
        return await CryptoExchangeLayer.privateKeyToPublicKey(privateKey);
    }

    /**
     * Asynchronously generates a key pair handle for cryptographic key exchange using the crypto layer.
     */
    public static async generateKeypairHandle(
        providerIdent: ProviderIdentifier,
        spec: KeyPairSpec
    ): Promise<CryptoExchangeKeypairHandle> {
        return await CryptoExchangeLayer.generateKeypair(providerIdent, spec);
    }

    /**
     * Derives shared secrets for key exchange in the 'requestor' role using crypto-layer.
     * This method properly delegates to the CAL implementation.
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
        // Removed unnecessary type casting
        if (
            !(requestorKeypair instanceof CryptoExchangeKeypairHandle) &&
            !(templatorPublicKey instanceof CryptoExchangePublicKeyHandle)
        ) {
            return await super.deriveRequestor(requestorKeypair, templatorPublicKey, algorithm);
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
        // Removed unnecessary type casting
        if (
            !(templatorKeypair instanceof CryptoExchangeKeypairHandle) &&
            !(requestorPublicKey instanceof CryptoExchangePublicKeyHandle)
        ) {
            return await super.deriveTemplator(templatorKeypair, requestorPublicKey, algorithm);
        }

        // If we get here, there's a mismatch in types
        throw new CryptoError(
            CryptoErrorCode.ExchangeWrongAlgorithm,
            "Mismatch in keypair types: both must be either traditional or handle-based"
        );
    }
}
