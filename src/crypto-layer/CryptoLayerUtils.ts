import { Argon2Options, AsymmetricKeySpec, Cipher, CryptoHash, KDF } from "@nmshd/rs-crypto-types";
import { CryptoDerivationAlgorithm, CryptoEncryptionAlgorithm } from "..";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoExchangeAlgorithm } from "../exchange/CryptoExchange";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "../signature/CryptoSignatureAlgorithm";

export class CryptoLayerUtils {
    public static asymSpecFromCryptoExchangeOrSignatureAlgorithm(
        algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
    ): AsymmetricKeySpec {
        switch (algorithm) {
            case CryptoExchangeAlgorithm.ECDH_P256:
                return "P256";
            case CryptoExchangeAlgorithm.ECDH_P521:
                return "P521";
            case CryptoExchangeAlgorithm.ECDH_X25519:
                return "Curve25519";
            case CryptoSignatureAlgorithm.ECDSA_P256:
                return "P256";
            case CryptoSignatureAlgorithm.ECDSA_P521:
                return "P521";
            case CryptoSignatureAlgorithm.ECDSA_ED25519:
                return "Curve25519";
            case CryptoSignatureAlgorithm.RSA_2048:
                return "RSA2048";
        }
    }

    public static cryptoHashAlgorithmFromCryptoHash(cryptoHash: CryptoHash): CryptoHashAlgorithm {
        // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
        switch (cryptoHash) {
            case "Sha2_256":
                return CryptoHashAlgorithm.SHA256;
            case "Sha2_512":
                return CryptoHashAlgorithm.SHA512;
            case "Blake2b":
                return CryptoHashAlgorithm.BLAKE2B;
            default:
                throw new CryptoError(
                    CryptoErrorCode.CalUnsupportedAlgorithm,
                    `Hash function ${cryptoHash} is not supported by ts crypto.`
                );
        }
    }

    public static cryptoHashFromCryptoHashAlgorithm(algorithm: CryptoHashAlgorithm): CryptoHash {
        switch (algorithm) {
            case CryptoHashAlgorithm.SHA256:
                return "Sha2_256";
            case CryptoHashAlgorithm.SHA512:
                return "Sha2_512";
            case CryptoHashAlgorithm.BLAKE2B:
                return "Blake2b";
        }
    }

    public static cipherFromCryptoEncryptionAlgorithm(alg: CryptoEncryptionAlgorithm): Cipher {
        switch (alg) {
            case CryptoEncryptionAlgorithm.AES128_GCM:
                return "AesGcm128";
            case CryptoEncryptionAlgorithm.AES256_GCM:
                return "AesGcm256";
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                return "XChaCha20Poly1305";
            case CryptoEncryptionAlgorithm.AES128_CBC:
                return "AesCbc128";
            case CryptoEncryptionAlgorithm.AES256_CBC:
                return "AesCbc256";
            case CryptoEncryptionAlgorithm.CHACHA20_POLY1305:
                return "ChaCha20Poly1305";
        }
    }

    public static cryptoEncryptionAlgorithmFromCipher(cipher: Cipher): CryptoEncryptionAlgorithm {
        switch (cipher) {
            case "AesGcm128":
                return CryptoEncryptionAlgorithm.AES128_GCM;
            case "AesGcm256":
                return CryptoEncryptionAlgorithm.AES256_GCM;
            case "AesCbc128":
                return CryptoEncryptionAlgorithm.AES128_CBC;
            case "AesCbc256":
                return CryptoEncryptionAlgorithm.AES256_CBC;
            case "XChaCha20Poly1305":
                return CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;
            case "ChaCha20Poly1305":
                return CryptoEncryptionAlgorithm.CHACHA20_POLY1305;
        }
    }

    public static argon2OptionsFromIterationsMemLimitAndParallelism(
        iterations: number,
        memlimit: number,
        parallelism: number
    ): Argon2Options {
        const kibiByteBase = 2 ^ 10;
        if (memlimit % kibiByteBase !== 0) {
            throw new CryptoError(
                CryptoErrorCode.WrongParameters,
                "rust-crypto uses kibibytes for Argon2. The `memlimit` parameter (in bytes) is not a multiple of `2^10` and thus not convertible without loss."
            ).setContext(CryptoLayerUtils.argon2OptionsFromIterationsMemLimitAndParallelism);
        }
        const memory = memlimit / kibiByteBase;

        const options: Argon2Options = {
            memory: memory,
            iterations: iterations,
            parallelism: parallelism
        };

        return options;
    }

    public static kdfFromCryptoDerivation(
        derivationAlgorithm: CryptoDerivationAlgorithm,
        iterations: number,
        memlimit: number,
        parallelism: number
    ): KDF {
        const options: Argon2Options = CryptoLayerUtils.argon2OptionsFromIterationsMemLimitAndParallelism(
            iterations,
            memlimit,
            parallelism
        );

        switch (derivationAlgorithm) {
            case CryptoDerivationAlgorithm.ARGON2ID:
                // eslint-disable-next-line @typescript-eslint/naming-convention
                return { Argon2id: options };
            case CryptoDerivationAlgorithm.ARGON2I:
                // eslint-disable-next-line @typescript-eslint/naming-convention
                return { Argon2i: options };
            default:
                throw new CryptoError(
                    CryptoErrorCode.WrongParameters,
                    `Crypto derivation algorithm '${derivationAlgorithm}' not supported.`
                ).setContext(CryptoLayerUtils.kdfFromCryptoDerivation);
        }
    }
}
