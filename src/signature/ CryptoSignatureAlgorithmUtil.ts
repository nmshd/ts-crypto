import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSignatureAlgorithm } from "./CryptoSignatureAlgorithm";

export class CryptoSignatureAlgorithmUtil {
    public static toCalSigSpec(alg: CryptoSignatureAlgorithm): string {
        switch (alg) {
            case CryptoSignatureAlgorithm.ECDSA_P256:
                return "P256";
            case CryptoSignatureAlgorithm.ECDSA_P521:
                return "P521";
            case CryptoSignatureAlgorithm.ECDSA_ED25519:
                return "Ed25519";
            default:
                throw new CryptoError(
                    CryptoErrorCode.SignatureWrongAlgorithm,
                    `Unsupported signature algorithm: ${alg}`
                );
        }
    }

    public static fromCalSigSpec(spec: string): CryptoSignatureAlgorithm {
        switch (spec) {
            case "P256":
                return CryptoSignatureAlgorithm.ECDSA_P256;
            case "P521":
                return CryptoSignatureAlgorithm.ECDSA_P521;
            case "Ed25519":
                return CryptoSignatureAlgorithm.ECDSA_ED25519;
            default:
                throw new CryptoError(
                    CryptoErrorCode.SignatureWrongAlgorithm,
                    `Unsupported asymmetric key spec: ${spec}`
                );
        }
    }
}
