import { CryptoHash } from "@nmshd/rs-crypto-types";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoHashAlgorithm } from "./CryptoHash";

export class CryptoHashAlgorithmUtil {
    public static toCalHash(alg: CryptoHashAlgorithm): CryptoHash {
        switch (alg) {
            case CryptoHashAlgorithm.SHA256:
                return "Sha2_256";
            case CryptoHashAlgorithm.SHA512:
                return "Sha2_512";
            case CryptoHashAlgorithm.BLAKE2B:
                throw new CryptoError(
                    CryptoErrorCode.NotYetImplemented,
                    "BLAKE2B is not yet implemented for KeySpec conversion."
                );
            default:
                throw new CryptoError(CryptoErrorCode.EncryptionWrongAlgorithm, `Unsupported hash algorithm: ${alg}`);
        }
    }

    public static fromCalHash(hash: CryptoHash): CryptoHashAlgorithm {
        switch (hash) {
            case "Sha2_256":
                return CryptoHashAlgorithm.SHA256;
            case "Sha2_512":
                return CryptoHashAlgorithm.SHA512;
            default:
                throw new CryptoError(CryptoErrorCode.EncryptionWrongAlgorithm, `Unsupported hash: ${hash}`);
        }
    }
}
