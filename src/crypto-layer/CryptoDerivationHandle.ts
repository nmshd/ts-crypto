import { Cipher, CryptoHash, KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { ICoreBuffer } from "src/CoreBuffer";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoSerializableAsync } from "src/CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "src/encryption/CryptoEncryption";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "./encryption/CryptoSecretKeyHandle";

let handleDerivationInitialized = false;

export function initCryptoDerivationHandle(): void {
    handleDerivationInitialized = true;
}

/**
 * Provides handle-based derivation methods.
 */
export class CryptoDerivationHandle extends CryptoSerializableAsync {
    /**
     * Derives a handle-based key from a password using the provider's native Argon2 implementation.
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
