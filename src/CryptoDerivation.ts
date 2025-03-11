import { CoreBuffer, ICoreBuffer } from "./CoreBuffer";
import { CryptoDerivationHandle, initCryptoDerivationHandle } from "./crypto-layer/CryptoDerivationHandle";
import { CryptoEncryptionAlgorithm } from "./encryption/CryptoEncryption";
import { CryptoSecretKey } from "./encryption/CryptoSecretKey";
import { SodiumWrapper } from "./SodiumWrapper";

/**
 * The key derivation algorithm to use
 */
export const enum CryptoDerivationAlgorithm {
    ARGON2I = "argon2i",
    ARGON2ID = "argon2id"
}

export interface ICryptoDerivation {}

export interface ICryptoDerivationStatic {
    new (): ICryptoDerivation;

    deriveKeyFromPassword(
        masterKey: ICoreBuffer,
        salt: ICoreBuffer,
        keyAlgorithm: CryptoEncryptionAlgorithm,
        derivationAlgorithm: CryptoDerivationAlgorithm,
        iterations: number,
        memlimit: number
    ): Promise<CryptoSecretKey>;
    deriveKeyFromBase(
        baseKey: ICoreBuffer,
        keyId: number,
        context: string,
        keyAlgorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoSecretKey>;
}

/**
 * The original libsodium-based class, preserving your old logic exactly.
 */
export class CryptoDerivationWithLibsodium implements ICryptoDerivation {
    public static async deriveKeyFromPassword(
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keyAlgorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
        derivationAlgorithm: CryptoDerivationAlgorithm = CryptoDerivationAlgorithm.ARGON2ID,
        opslimit = 100000,
        memlimit = 8192
    ): Promise<CryptoSecretKey> {
        const sodium: any = await SodiumWrapper.ready();
        if (salt.buffer.byteLength !== sodium.crypto_pwhash_SALTBYTES) {
            throw new Error(`The salt must be exactly ${sodium.crypto_pwhash_SALTBYTES} bytes long!`);
        }

        if (opslimit < sodium.crypto_pwhash_OPSLIMIT_MIN) {
            throw new Error(`opslimit must be >= ${sodium.crypto_pwhash_OPSLIMIT_MIN}.`);
        }
        if (sodium.crypto_pwhash_OPSLIMIT_MAX > 0 && opslimit > sodium.crypto_pwhash_OPSLIMIT_MAX) {
            throw new Error(`opslimit must be <= ${sodium.crypto_pwhash_OPSLIMIT_MAX}.`);
        }

        if (memlimit < sodium.crypto_pwhash_MEMLIMIT_MIN) {
            throw new Error(`memlimit must be >= ${sodium.crypto_pwhash_MEMLIMIT_MIN}.`);
        }
        if (sodium.crypto_pwhash_MEMLIMIT_MAX > 0 && memlimit > sodium.crypto_pwhash_MEMLIMIT_MAX) {
            throw new Error(`memlimit must be <= ${sodium.crypto_pwhash_MEMLIMIT_MAX}.`);
        }

        let keyLength;
        switch (keyAlgorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
                keyLength = 16;
                break;
            case CryptoEncryptionAlgorithm.AES256_GCM:
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                keyLength = 32;
                break;
            default:
                throw new Error("Unsupported key algorithm in libsodium derivation.");
        }

        let argonAlgorithm: number;
        switch (derivationAlgorithm) {
            case CryptoDerivationAlgorithm.ARGON2I:
                argonAlgorithm = 1; // numeric representation
                break;
            case CryptoDerivationAlgorithm.ARGON2ID:
                argonAlgorithm = 2; // numeric representation
                break;
            default:
                throw new Error("Unsupported derivation algorithm.");
        }

        const pwhash = sodium.crypto_pwhash(
            keyLength,
            password.buffer,
            salt.buffer,
            opslimit,
            memlimit,
            argonAlgorithm
        );
        const hashBuffer = CoreBuffer.from(pwhash);

        return CryptoSecretKey.from({ secretKey: hashBuffer, algorithm: keyAlgorithm });
    }

    public static async deriveKeyFromBase(
        baseKey: ICoreBuffer,
        keyId: number,
        context: string,
        keyAlgorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoSecretKey> {
        if (context.length !== 8) {
            throw new Error("The context must be exactly 8 characters long.");
        }
        let keyLength: number;
        switch (keyAlgorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
                keyLength = 16;
                break;
            case CryptoEncryptionAlgorithm.AES256_GCM:
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                keyLength = 32;
                break;
            default:
                throw new Error("Unsupported key algorithm in libsodium base derivation.");
        }

        const sodium = await SodiumWrapper.ready();
        const subkey = sodium.crypto_kdf_derive_from_key(keyLength, keyId, context, baseKey.buffer);

        return CryptoSecretKey.from({ secretKey: CoreBuffer.fromObject(subkey), algorithm: keyAlgorithm });
    }
}

/**
 * A simple boolean for whether handle-based usage is available for derivation.
 */
let derivationProviderInitialized = false;

/**
 * Call this if you have a provider for handle-based derivation.
 * Also calls initCryptoDerivationHandle() if needed.
 */
export function initCryptoDerivation(): void {
    derivationProviderInitialized = true;
    // If you want, you can also call initCryptoDerivationHandle() or do it externally
    initCryptoDerivationHandle();
}

/**
 * The new extended class that can do handle-based derivation if a provider is available,
 * or fall back to libsodium if not.
 */
export class CryptoDerivation extends CryptoDerivationWithLibsodium {
    /**
     * If handle-based usage is enabled, do a handle-based approach via CryptoDerivationHandle.
     * Otherwise, fallback to libsodium logic.
     */
    public static override async deriveKeyFromPassword(
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keyAlgorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
        derivationAlgorithm: CryptoDerivationAlgorithm = CryptoDerivationAlgorithm.ARGON2ID,
        opslimit = 100000,
        memlimit = 8192
    ): Promise<CryptoSecretKey> {
        if (derivationProviderInitialized) {
            const derivedKey = await CryptoDerivationHandle.deriveKeyFromPasswordHandle(
                { providerName: "SoftwareProvider" },
                password,
                salt,
                keyAlgorithm
            );
            return await CryptoSecretKey.fromHandle(derivedKey);
        }
        // fallback to libsodium
        return await super.deriveKeyFromPassword(password, salt, keyAlgorithm, derivationAlgorithm, opslimit, memlimit);
    }

    public static override async deriveKeyFromBase(
        baseKey: ICoreBuffer,
        keyId: number,
        context: string,
        keyAlgorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoSecretKey> {
        if (derivationProviderInitialized) {
            const derivedKey = await CryptoDerivationHandle.deriveKeyFromBaseHandle(
                { providerName: "SoftwareProvider" },
                baseKey,
                keyId,
                context,
                keyAlgorithm
            );
            return await CryptoSecretKey.fromHandle(derivedKey);
        }
        // fallback
        return await super.deriveKeyFromBase(baseKey, keyId, context, keyAlgorithm);
    }
}
