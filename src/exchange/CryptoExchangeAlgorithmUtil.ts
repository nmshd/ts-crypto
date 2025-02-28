import { AsymmetricKeySpec } from "@nmshd/rs-crypto-types";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoExchangeAlgorithm } from "./CryptoExchange";

export class CryptoExchangeAlgorithmUtil {
    public static toCalAsymSpec(alg: CryptoExchangeAlgorithm): AsymmetricKeySpec {
        switch (alg) {
            case CryptoExchangeAlgorithm.ECDH_P256:
                return "P256";
            case CryptoExchangeAlgorithm.ECDH_P521:
                return "P521";
            case CryptoExchangeAlgorithm.ECDH_X25519:
                return "Curve25519";
            default:
                throw new CryptoError(CryptoErrorCode.ExchangeWrongAlgorithm, `Unsupported exchange algorithm: ${alg}`);
        }
    }

    public static fromCalAsymSpec(spec: AsymmetricKeySpec): CryptoExchangeAlgorithm {
        switch (spec) {
            case "P256":
                return CryptoExchangeAlgorithm.ECDH_P256;
            case "P521":
                return CryptoExchangeAlgorithm.ECDH_P521;
            case "Curve25519":
                return CryptoExchangeAlgorithm.ECDH_X25519;
            default:
                throw new CryptoError(
                    CryptoErrorCode.ExchangeWrongAlgorithm,
                    `Unsupported asymmetric key spec: ${spec}`
                );
        }
    }
}
