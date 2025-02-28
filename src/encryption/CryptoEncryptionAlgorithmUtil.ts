import { Cipher } from "@nmshd/rs-crypto-types";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "./CryptoEncryption";

export class CryptoEncryptionAlgorithmUtil {
    public static toCalCipher(alg: CryptoEncryptionAlgorithm): Cipher {
        switch (alg) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
                return "AesGcm128";
            case CryptoEncryptionAlgorithm.AES256_GCM:
                return "AesGcm256";
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                return "XChaCha20Poly1305";
        }
    }

    public static fromCalCipher(cipher: Cipher): CryptoEncryptionAlgorithm {
        switch (cipher) {
            case "AesGcm128":
                return CryptoEncryptionAlgorithm.AES128_GCM;
            case "AesGcm256":
                return CryptoEncryptionAlgorithm.AES256_GCM;
            case "XChaCha20Poly1305":
                return CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;
            default:
                throw new CryptoError(CryptoErrorCode.EncryptionWrongAlgorithm, `Unsupported cipher: ${cipher}`);
        }
    }
}
