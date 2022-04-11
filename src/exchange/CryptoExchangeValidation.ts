import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoExchangeAlgorithm } from "./CryptoExchange";
import { CryptoExchangePrivateKey } from "./CryptoExchangePrivateKey";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";

export class CryptoExchangeValidation extends CryptoValidation {
    public static readonly PRIVATE_KEY_MIN_BYTES = 20;
    public static readonly PRIVATE_KEY_MAX_BYTES = 40;
    public static readonly PUBLIC_KEY_MIN_BYTES = 20;
    public static readonly PUBLIC_KEY_MAX_BYTES = 40;

    public static checkExchangeAlgorithm(algorithm: number, throwError = true): CryptoError | undefined {
        let error;
        switch (algorithm) {
            case CryptoExchangeAlgorithm.ECDH_P256:
            case CryptoExchangeAlgorithm.ECDH_P521:
            case CryptoExchangeAlgorithm.ECDH_X25519:
                break;
            default:
                error = new CryptoError(
                    CryptoErrorCode.ExchangeWrongAlgorithm,
                    "Exchange algorithm is not set or supported."
                );
                break;
        }
        if (error && throwError) throw error;
        return error;
    }

    public static checkExchangePrivateKeyAsNumber(
        privateKey: string,
        algorithm: CryptoExchangeAlgorithm,
        propertyName = "privateKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkSerializedBuffer(
            privateKey,
            this.PRIVATE_KEY_MIN_BYTES,
            this.PRIVATE_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkExchangePrivateKeyAsBuffer(
        privateKey: CoreBuffer,
        algorithm: CryptoExchangeAlgorithm,
        propertyName = "privateKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkBuffer(
            privateKey,
            this.PRIVATE_KEY_MIN_BYTES,
            this.PRIVATE_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkExchangePrivateKey(
        privateKey: CryptoExchangePrivateKey,
        throwError = true
    ): CryptoError | undefined {
        let error;
        if (!(privateKey instanceof CryptoExchangePrivateKey)) {
            error = new CryptoError(CryptoErrorCode.ExchangeWrongPrivateKey, "PrivateKey is not set or supported.");
        }
        if (error && throwError) throw error;
        return error;
    }

    public static checkExchangePublicKeyAsString(
        publicKey: string,
        algorithm: CryptoExchangeAlgorithm,
        propertyName = "publicKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkSerializedBuffer(
            publicKey,
            this.PRIVATE_KEY_MIN_BYTES,
            this.PRIVATE_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkExchangePublicKeyAsBuffer(
        publicKey: CoreBuffer,
        algorithm: CryptoExchangeAlgorithm,
        propertyName = "publicKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkBuffer(
            publicKey,
            this.PRIVATE_KEY_MIN_BYTES,
            this.PRIVATE_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkExchangePublicKey(
        publicKey: CryptoExchangePublicKey,
        throwError = true
    ): CryptoError | undefined {
        let error;
        if (!(publicKey instanceof CryptoExchangePublicKey)) {
            error = new CryptoError(CryptoErrorCode.ExchangeWrongPublicKey, "PublicKey is not set or supported.");
        }
        if (error && throwError) throw error;
        return error;
    }

    public static checkExchangeKeypair(
        privateKey: CryptoExchangePrivateKey,
        publicKey: CryptoExchangePublicKey,
        throwError = true
    ): CryptoError | undefined {
        let error;
        error = this.checkExchangePublicKey(publicKey);
        if (error && throwError) throw error;
        else if (error) return error;
        error = this.checkExchangePrivateKey(privateKey);
        if (error && throwError) throw error;
        else if (error) return error;

        if (privateKey.algorithm !== publicKey.algorithm) {
            error = new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                "Algorithms of private and public key do not match."
            );
        }
        if (error && throwError) throw error;
        return error;
    }
}
