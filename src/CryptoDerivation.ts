import { CoreBuffer, Encoding, ICoreBuffer } from "./CoreBuffer";
import { CryptoEncryptionAlgorithm } from "./encryption/CryptoEncryption";
import { CryptoSecretKey } from "./encryption/CryptoSecretKey";
import { SodiumWrapper } from "./SodiumWrapper";

/**
 * The key derivation algorithm to use
 */
export const enum CryptoDerivationAlgorithm {
    PBKDF2 = "pbkdf2"
}

export interface ICryptoDerivation {}

export interface ICryptoDerivationStatic {
    new (): ICryptoDerivation;

    deriveKeyFromMaster(
        masterKey: ICoreBuffer,
        iterations: number,
        keyAlgorithm: CryptoEncryptionAlgorithm,
        salt?: ICoreBuffer
    ): Promise<CryptoSecretKey>;
    deriveKeyFromBase(
        baseKey: ICoreBuffer,
        keyId: number,
        context: string,
        keyAlgorithm: CryptoEncryptionAlgorithm
    ): Promise<CryptoSecretKey>;
}

export class CryptoDerivation implements ICryptoDerivation {
    public static async deriveKeyFromMaster(
        masterKey: ICoreBuffer,
        iterations: number,
        keyAlgorithm: CryptoEncryptionAlgorithm,
        salt?: ICoreBuffer
    ): Promise<CryptoSecretKey> {
        switch (keyAlgorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
            case CryptoEncryptionAlgorithm.AES256_GCM:
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                break;
            default:
                throw new Error("KeyAlgorithm not supported.");
        }
        const saltedMaster: ICoreBuffer = masterKey;

        if (typeof salt !== "undefined") {
            saltedMaster.append(salt);
        }

        const memLimit = 2000;

        const pwhash = (await SodiumWrapper.ready()).crypto_pwhash_str(saltedMaster.buffer, iterations, memLimit);
        const hashBuffer = CoreBuffer.fromString(pwhash, Encoding.Hex);
        return CryptoSecretKey.from({ secretKey: hashBuffer, algorithm: keyAlgorithm });
    }

    public static async deriveKeyFromBase(
        baseKey: ICoreBuffer,
        keyId: number,
        context: string,
        keyAlgorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoSecretKey> {
        if (context.length !== 8) {
            throw new Error("The context should be exactly 8 characters long!");
        }
        let keyLength: number;
        switch (keyAlgorithm) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
                keyLength = 16;
                break;
            case CryptoEncryptionAlgorithm.AES256_GCM:
                keyLength = 32;
                break;
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                keyLength = 32;
                break;
            default:
                throw new Error("KeyAlgorithm not supported.");
        }
        const subkey = (await SodiumWrapper.ready()).crypto_kdf_derive_from_key(
            keyLength,
            keyId,
            context,
            baseKey.buffer
        );
        return CryptoSecretKey.from({ secretKey: CoreBuffer.fromObject(subkey), algorithm: keyAlgorithm });
    }
}
