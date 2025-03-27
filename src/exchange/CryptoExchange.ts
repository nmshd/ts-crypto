import { DHExchange, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../CoreBuffer";
import { getProvider, ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { CryptoExchangeWithCryptoLayer } from "../crypto-layer/exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../crypto-layer/exchange/CryptoExchangeKeypairHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoExchangeKeypair } from "./CryptoExchangeKeypair";
import { CryptoExchangePrivateKey } from "./CryptoExchangePrivateKey";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeSecrets } from "./CryptoExchangeSecrets";

/**
 * The key exchange algorithm to use.
 */
export const enum CryptoExchangeAlgorithm {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P256 = 1,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P521 = 2,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_X25519 = 3
}

export class CryptoExchangeWithLibsodium {
    public static async generateKeypair(
        algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_X25519
    ): Promise<CryptoExchangeKeypair> {
        let privateKeyBuffer: Uint8Array;
        let publicKeyBuffer: Uint8Array;

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

        const privateKey = CryptoExchangePrivateKey.from({
            algorithm,
            privateKey: CoreBuffer.from(privateKeyBuffer)
        });
        const publicKey = CryptoExchangePublicKey.from({
            algorithm,
            publicKey: CoreBuffer.from(publicKeyBuffer)
        });
        return CryptoExchangeKeypair.from({ publicKey, privateKey });
    }

    public static async deriveRequestor(
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
        return CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
    }

    public static async deriveTemplator(
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
        } catch (e: any) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
        return CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
    }
}

let providerInitialized = false;

export function initCryptoExchange(providerIdent: ProviderIdentifier): void {
    if (getProvider(providerIdent)) {
        providerInitialized = true;
    }
}

/**
 * Extended CryptoExchange class.
 *
 * The methods accept a keypair whose private key may be either a traditional (libsodium-generated)
 * key (an instance of CryptoExchangePrivateKey) or a crypto-layer–backed key (an instance of
 * CryptoExchangeKeypairHandle). Similarly, the public key parameters may be either type.
 * Based on the key type (as determined by a helper property such as isCryptoLayerKey),
 * the corresponding implementation is called.
 */
export class CryptoExchange extends CryptoExchangeWithLibsodium {
    public static async generateKeypairHandle(
        providerIdent: ProviderIdentifier,
        spec: KeyPairSpec
    ): Promise<CryptoExchangeKeypairHandle> {
        return await CryptoExchangeWithCryptoLayer.generateKeypair(providerIdent, spec);
    }

    /**
     * Derives session keys (requestor/server role).
     *
     * Dispatches to either libsodium or crypto-layer based on argument types:
     * - Libsodium: If `requestorKeypair` is [[CryptoExchangeKeypair]] and `templatorPublicKey` is [[CryptoExchangePublicKey]].
     * - Crypto-Layer: If `requestorKeypair` is [[DHExchange]] and `templatorPublicKey` is `Uint8Array`. Requires initialized provider.
     *
     * @param requestorKeypair The keypair/handle of the sending side ([[CryptoExchangeKeypair]] or [[DHExchange]]).
     * @param templatorPublicKey The public key of the receiving side ([[CryptoExchangePublicKey]] or `Uint8Array`).
     * @param algorithm The [[CryptoEncryptionAlgorithm]] to tag the derived secrets with.
     *                  Defaults to XCHACHA20_POLY1305 (libsodium default) or AES256_GCM (crypto-layer default) depending on the path taken.
     *                  *Note*: Consider explicitly passing the desired algorithm.
     * @returns A Promise resolving into a [[CryptoExchangeSecrets]] object.
     * @throws {CryptoError} If argument types are incompatible, provider unavailable, or derivation fails.
     */
    public static override async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair | DHExchange,
        templatorPublicKey: CryptoExchangePublicKey | Uint8Array,
        algorithm?: CryptoEncryptionAlgorithm
    ): Promise<CryptoExchangeSecrets> {
        if (
            providerInitialized &&
            !(requestorKeypair instanceof CryptoExchangeKeypair) &&
            templatorPublicKey instanceof Uint8Array
        ) {
            try {
                const effectiveAlgorithm = algorithm ?? CryptoEncryptionAlgorithm.AES256_GCM;
                return await CryptoExchangeWithCryptoLayer.deriveRequestor(
                    requestorKeypair,
                    templatorPublicKey,
                    effectiveAlgorithm
                );
            } catch (e: any) {
                if (e instanceof CryptoError) throw e;
                throw new CryptoError(
                    CryptoErrorCode.ExchangeKeyDerivation,
                    `Crypto-layer key derivation (requestor) failed: ${e}`
                );
            }
        }

        if (
            requestorKeypair instanceof CryptoExchangeKeypair &&
            templatorPublicKey instanceof CryptoExchangePublicKey
        ) {
            const effectiveAlgorithm = algorithm ?? CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;
            return await super.deriveRequestor(requestorKeypair, templatorPublicKey, effectiveAlgorithm);
        }

        // --- Incompatible Arguments ---
        throw new CryptoError(
            CryptoErrorCode.WrongParameters, // Use a more specific error code
            "Incompatible argument types for deriveRequestor. Provide (CryptoExchangeKeypair, CryptoExchangePublicKey) for libsodium OR (DHExchange, Uint8Array) for crypto-layer."
        );
    }

    /**
     * Derives session keys (templator/client role).
     *
     * Dispatches to either libsodium or crypto-layer based on argument types:
     * - Libsodium: If `templatorKeypair` is [[CryptoExchangeKeypair]] and `requestorPublicKey` is [[CryptoExchangePublicKey]].
     * - Crypto-Layer: If `templatorKeypair` is [[DHExchange]] and `requestorPublicKey` is `Uint8Array`. Requires initialized provider.
     *
     * @param templatorKeypair The keypair/handle of the receiving side ([[CryptoExchangeKeypair]] or [[DHExchange]]).
     * @param requestorPublicKey The public key of the sending side ([[CryptoExchangePublicKey]] or `Uint8Array`).
     * @param algorithm The [[CryptoEncryptionAlgorithm]] to tag the derived secrets with.
     *                  Defaults to XCHACHA20_POLY1305 (libsodium default) or AES256_GCM (crypto-layer default) depending on the path taken.
     *                  *Note*: Consider explicitly passing the desired algorithm.
     * @returns A Promise resolving into a [[CryptoExchangeSecrets]] object.
     * @throws {CryptoError} If argument types are incompatible, provider unavailable, or derivation fails.
     */
    public static override async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair | DHExchange,
        requestorPublicKey: CryptoExchangePublicKey | Uint8Array,
        algorithm?: CryptoEncryptionAlgorithm
    ): Promise<CryptoExchangeSecrets> {
        if (
            providerInitialized &&
            !(templatorKeypair instanceof CryptoExchangeKeypair) &&
            requestorPublicKey instanceof Uint8Array
        ) {
            try {
                const effectiveAlgorithm = algorithm ?? CryptoEncryptionAlgorithm.AES256_GCM;
                return await CryptoExchangeWithCryptoLayer.deriveTemplator(
                    templatorKeypair,
                    requestorPublicKey,
                    effectiveAlgorithm
                );
            } catch (e: any) {
                if (e instanceof CryptoError) throw e;
                throw new CryptoError(
                    CryptoErrorCode.ExchangeKeyDerivation,
                    `Crypto-layer key derivation (templator) failed: ${e}`
                );
            }
        }

        if (
            templatorKeypair instanceof CryptoExchangeKeypair &&
            requestorPublicKey instanceof CryptoExchangePublicKey
        ) {
            const effectiveAlgorithm = algorithm ?? CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;
            return await super.deriveTemplator(templatorKeypair, requestorPublicKey, effectiveAlgorithm);
        }

        throw new CryptoError(
            CryptoErrorCode.WrongParameters,
            "Incompatible argument types for deriveTemplator. Provide (CryptoExchangeKeypair, CryptoExchangePublicKey) for libsodium OR (DHExchange, Uint8Array) for crypto-layer."
        );
    }
}
