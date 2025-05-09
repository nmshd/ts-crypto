import { CryptoHash, KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { ICoreBuffer } from "../CoreBuffer";
import { CryptoDerivationAlgorithm } from "../CryptoDerivation";
import { CryptoSerializableAsync } from "../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "./encryption/CryptoSecretKeyHandle";

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
    public static async deriveKeyFromPassword(
        providerIdent: ProviderIdentifier,
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keyAlgorithm: CryptoEncryptionAlgorithm,
        derivationAlgorithm: CryptoDerivationAlgorithm,
        opslimit = 100000,
        memlimit = 8192
    ): Promise<CryptoSecretKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const signingHash: CryptoHash = "Sha2_512";

        const spec: KeySpec = {
            cipher: CryptoEncryptionAlgorithm.toCalCipher(keyAlgorithm),
            ephemeral: true,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            signing_hash: signingHash
        };

        // Create the KDF options
        let kdfOptions: KDF;
        switch (derivationAlgorithm) {
            case CryptoDerivationAlgorithm.ARGON2I: {
                // TODO: it should be Argon2i and not d, need to update ts-types
                // eslint-disable-next-line @typescript-eslint/naming-convention
                kdfOptions = { Argon2d: { memory: memlimit, iterations: opslimit, parallelism: 1 } };
            }
            case CryptoDerivationAlgorithm.ARGON2ID: {
                // eslint-disable-next-line @typescript-eslint/naming-convention
                kdfOptions = { Argon2id: { memory: memlimit, iterations: opslimit, parallelism: 1 } };
            }
        }

        // Now call deriveKeyFromPassword with the additional kdf parameter.
        const keyHandle = await provider.deriveKeyFromPassword(password.toUtf8(), salt.buffer, spec, kdfOptions);

        return await CryptoSecretKeyHandle.newFromProviderAndKeyHandle(provider, keyHandle);
    }

    // /**
    //  * Derives a cryptographic key from a base key using a key derivation function.
    //  * This method enables hierarchical key derivation, which is useful for creating
    //  * multiple independent keys from a single master key.
    //  *
    //  * @param providerIdent - Identifier for the crypto provider to be used for key derivation.
    //  * @param baseKey - The base key buffer from which to derive the new key.
    //  * @param keyId - A numeric identifier for the derived key, allowing multiple keys to be derived from the same base.
    //  * @param context - A string context that provides additional domain separation.
    //  * @param keyAlgorithm - The encryption algorithm for which the key will be used.
    //  * @returns A Promise that resolves to a {@link CryptoSecretKeyHandle} containing the derived key.
    //  * @throws {@link CryptoError} with {@link CryptoErrorCode.CalUninitializedKey} if the derivation system is not initialized.
    //  * @throws {@link CryptoError} with {@link CryptoErrorCode.EncryptionWrongAlgorithm} if the key algorithm is not supported.
    //  */
    // public static async deriveKeyFromBase(
    //     providerIdent: ProviderIdentifier,
    //     baseKey: ICoreBuffer,
    //     keyId: number,
    //     context: string,
    //     keyAlgorithm: CryptoEncryptionAlgorithm
    // ): Promise<CryptoSecretKeyHandle> {
    //     const provider = getProviderOrThrow(providerIdent);
    //     const cipherName = CryptoEncryptionAlgorithm.toCalCipher(keyAlgorithm);

    //     const spec: KeySpec = {
    //         cipher: cipherName,
    //         ephemeral: true,
    //         // eslint-disable-next-line @typescript-eslint/naming-convention
    //         signing_hash: "Sha2_512"
    //     };

    //     const keyHandle = await provider.deriveKeyFromBase(baseKey.buffer, keyId, context, spec);

    //     return await CryptoSecretKeyHandle.newFromProviderAndKeyHandle(provider, keyHandle, {
    //         keySpec: spec,
    //         algorithm: keyAlgorithm
    //     });
    // }

    /**
     * Derive an ephemeral {@link CryptoSecretKeyHandle} from another with the same key spec and algorithm.
     *
     * @param baseKey Basekey to derive the new key from.
     * @param keyId A numeric identifier for the derived key, allowing multiple keys to be derived from the same base.
     * @param context A string context that provides additional domain separation.
     * @returns A promise resolving to an ephemeral key handle.
     */
    public static async deriveKeyHandleFromBase(
        baseKey: CryptoSecretKeyHandle,
        keyId: number,
        context: string
    ): Promise<CryptoSecretKeyHandle> {
        const encoder = new TextEncoder();
        const bytes = encoder.encode(`id:${keyId};ctx:${context}`);
        const derived = await baseKey.keyHandle.deriveKey(bytes);
        return await CryptoSecretKeyHandle.newFromProviderAndKeyHandle(baseKey.provider, derived);
    }
}
