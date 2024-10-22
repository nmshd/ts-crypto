import { CoreBuffer, ICoreBuffer } from "./CoreBuffer";
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

export class CryptoDerivation implements ICryptoDerivation {
    public static async deriveKeyFromPassword(
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keyAlgorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
        derivationAlgorithm: CryptoDerivationAlgorithm = CryptoDerivationAlgorithm.ARGON2ID,
        opslimit = 100000,
        memlimit = 8192
    ): Promise<CryptoSecretKey> {
        const sodium: any = (await SodiumWrapper.ready()) as any;
        if (salt.buffer.byteLength !== sodium.crypto_pwhash_SALTBYTES) {
            throw new Error(`The salt must be exactly ${sodium.crypto_pwhash_SALTBYTES} bytes long!`);
        }

        if (opslimit < sodium.crypto_pwhash_OPSLIMIT_MIN) {
            throw new Error(`The opslimit must be higher than ${sodium.crypto_pwhash_OPSLIMIT_MIN}.`);
        }

        if (sodium.crypto_pwhash_OPSLIMIT_MAX > 0 && opslimit > sodium.crypto_pwhash_OPSLIMIT_MAX) {
            throw new Error(`The opslimit must be lower than ${sodium.crypto_pwhash_OPSLIMIT_MAX}.`);
        }

        if (memlimit < sodium.crypto_pwhash_MEMLIMIT_MIN) {
            throw new Error(`The memlimit must be higher than ${sodium.crypto_pwhash_MEMLIMIT_MIN}.`);
        }

        if (sodium.crypto_pwhash_MEMLIMIT_MAX > 0 && memlimit > sodium.crypto_pwhash_MEMLIMIT_MAX) {
            throw new Error(`The memlimit must be lower than ${sodium.crypto_pwhash_MEMLIMIT_MAX}.`);
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
                throw new Error("KeyAlgorithm not supported.");
        }

        let derivationAlgorithmAsNumber: number;
        switch (derivationAlgorithm) {
            case CryptoDerivationAlgorithm.ARGON2I:
                derivationAlgorithmAsNumber = 1;
                break;
            case CryptoDerivationAlgorithm.ARGON2ID:
                derivationAlgorithmAsNumber = 2;
                break;
            default:
                throw new Error("DerivationAlgorithm not supported.");
        }

        const pwhash = (await SodiumWrapper.ready()).crypto_pwhash(
            keyLength,
            password.buffer,
            salt.buffer,
            opslimit,
            memlimit,
            derivationAlgorithmAsNumber
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
