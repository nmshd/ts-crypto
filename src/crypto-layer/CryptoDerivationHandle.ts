import { Cipher, CryptoHash, KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { ICoreBuffer } from "src/CoreBuffer";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoSerializableAsync } from "src/CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "src/encryption/CryptoEncryption";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "./encryption/CryptoSecretKeyHandle";

/**
 * Flag to track whether the derivation module has been initialized.
 * This ensures proper initialization before any cryptographic operations.
 */
let handleDerivationInitialized = false;

/**
 * Initializes the cryptographic derivation handle system.
 * Must be called before any derivation operations are performed.
 */
export function initCryptoDerivationHandle(): void {
    handleDerivationInitialized = true;
}

/**
 * Provides handle-based key derivation methods using the crypto layer.
 * This class implements secure key derivation functions for generating
 * cryptographic keys from passwords or base keys.
 */
export class CryptoDerivationHandle extends CryptoSerializableAsync {
    /**
     * Derives a cryptographic key from a password using the provider's native Argon2 implementation.
     * This method leverages the Argon2id algorithm for password-based key derivation, which
     * provides strong security against both side-channel and brute-force attacks.
     *
     * @param providerIdent - Identifier for the crypto provider to be used for key derivation.
     * @param password - The password buffer from which to derive the key.
     * @param salt - A cryptographically random salt buffer to prevent rainbow table attacks.
     * @param keyAlgorithm - The encryption algorithm for which the key will be used.
     * @param opslimit - The computational cost parameter (iterations). Defaults to 100000.
     * @param memlimit - The memory cost parameter in KiB. Defaults to 8192 (8 MB).
     * @returns A Promise that resolves to a {@link CryptoSecretKeyHandle} containing the derived key.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.CalUninitializedKey} if the derivation system is not initialized.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.EncryptionWrongAlgorithm} if the key algorithm is not supported.
     */
    public static async deriveKeyFromPasswordHandle(
        providerIdent: ProviderIdentifier,
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keyAlgorithm: CryptoEncryptionAlgorithm,
        opslimit = 100000,
        memlimit = 8192
    ): Promise<CryptoSecretKeyHandle> {
        if (!handleDerivationInitialized) {
            throw new CryptoError(CryptoErrorCode.CalUninitializedKey, "CryptoDerivationHandle not initialized.");
        }

        const provider = getProviderOrThrow(providerIdent);
        const signingHash: CryptoHash = "Sha2_512";

        const spec: KeySpec = {
            cipher: CryptoDerivationHandle.mapAlgorithmToCipherName(keyAlgorithm),
            ephemeral: true,
            signing_hash: signingHash
        };

        // Create the KDF options using Argon2id.
        const kdfOptions: KDF = { Argon2id: { memory: memlimit, iterations: opslimit, parallelism: 1 } };

        // Now call deriveKeyFromPassword with the additional kdf parameter.
        const keyHandle = await provider.deriveKeyFromPassword(password.toUtf8(), salt.buffer, spec, kdfOptions);

        return await CryptoSecretKeyHandle.newFromProviderAndKeyHandle(provider, keyHandle);
    }

    /**
     * Derives a cryptographic key from a base key using a key derivation function.
     * This method enables hierarchical key derivation, which is useful for creating
     * multiple independent keys from a single master key.
     *
     * @param providerIdent - Identifier for the crypto provider to be used for key derivation.
     * @param baseKey - The base key buffer from which to derive the new key.
     * @param keyId - A numeric identifier for the derived key, allowing multiple keys to be derived from the same base.
     * @param context - A string context that provides additional domain separation.
     * @param keyAlgorithm - The encryption algorithm for which the key will be used.
     * @returns A Promise that resolves to a {@link CryptoSecretKeyHandle} containing the derived key.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.CalUninitializedKey} if the derivation system is not initialized.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.EncryptionWrongAlgorithm} if the key algorithm is not supported.
     */
    public static async deriveKeyFromBaseHandle(
        providerIdent: ProviderIdentifier,
        baseKey: ICoreBuffer,
        keyId: number,
        context: string,
        keyAlgorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoSecretKeyHandle> {
        if (!handleDerivationInitialized) {
            throw new CryptoError(CryptoErrorCode.CalUninitializedKey, "CryptoDerivationHandle not initialized.");
        }

        const provider = getProviderOrThrow(providerIdent);
        const cipherName = CryptoDerivationHandle.mapAlgorithmToCipherName(keyAlgorithm);

        const spec: KeySpec = {
            cipher: cipherName,
            ephemeral: true,
            signing_hash: "Sha2_512"
        };

        const keyHandle = await provider.deriveKeyFromBase(baseKey.buffer, keyId, context, spec);

        return await CryptoSecretKeyHandle.newFromProviderAndKeyHandle(provider, keyHandle, {
            keySpec: spec,
            algorithm: keyAlgorithm
        });
    }

    /**
     * Maps a CryptoEncryptionAlgorithm to the corresponding Cipher type used by the crypto layer.
     * This internal utility method ensures proper translation between the application's algorithm
     * enumeration and the provider's cipher specification.
     *
     * @param keyAlgorithm - The encryption algorithm to map.
     * @returns The corresponding Cipher type for the crypto layer.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.EncryptionWrongAlgorithm} if the algorithm is not supported.
     */
    private static mapAlgorithmToCipherName(keyAlgorithm: CryptoEncryptionAlgorithm): Cipher {
        switch (keyAlgorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
                return "AesGcm128";
            case CryptoEncryptionAlgorithm.AES256_GCM:
                return "AesGcm256";
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                return "XChaCha20Poly1305";
            default:
                throw new CryptoError(CryptoErrorCode.EncryptionWrongAlgorithm, `Unsupported encryption algorithm.`);
        }
    }
}
