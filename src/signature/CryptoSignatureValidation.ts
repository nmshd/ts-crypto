import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoSignatureAlgorithm } from "./CryptoSignatureAlgorithm";

export class CryptoSignatureValidation extends CryptoValidation {
    public static readonly PRIVATE_KEY_MIN_BYTES = 20;
    public static readonly PRIVATE_KEY_MAX_BYTES = 80;
    public static readonly PUBLIC_KEY_MIN_BYTES = 20;
    public static readonly PUBLIC_KEY_MAX_BYTES = 80;
    public static readonly SIGNATURE_MIN_BYTES = 20;
    public static readonly SIGNATURE_MAX_BYTES = 100;

    public static checkSignatureAlgorithm(algorithm: number, throwError = true): CryptoError | undefined {
        let error: CryptoError | undefined;
        switch (algorithm) {
            case CryptoSignatureAlgorithm.ECDSA_ED25519:
            case CryptoSignatureAlgorithm.ECDSA_P256:
            case CryptoSignatureAlgorithm.ECDSA_P521:
                break;
            default:
                error = new CryptoError(
                    CryptoErrorCode.SignatureWrongAlgorithm,
                    "Signature algorithm is not set or supported."
                );
                break;
        }
        if (throwError && error) throw error;
        return error;
    }

    public static checkSignaturePrivateKeyAsString(
        key: string,
        propertyName = "privateKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkSerializedBuffer(
            key,
            this.PRIVATE_KEY_MIN_BYTES,
            this.PRIVATE_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkSignaturePrivateKeyAsBuffer(
        buffer: CoreBuffer,
        propertyName = "privateKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkBuffer(
            buffer,
            this.PRIVATE_KEY_MIN_BYTES,
            this.PRIVATE_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkSignaturePrivateKey(
        privateKey: string | CoreBuffer,
        propertyName = "privateKey",
        throwError = true
    ): CryptoError | undefined {
        if (typeof privateKey === "string") {
            return this.checkSignaturePrivateKeyAsString(privateKey, propertyName, throwError);
        }

        return this.checkSignaturePrivateKeyAsBuffer(privateKey, propertyName, throwError);
    }

    public static checkSignaturePublicKeyAsString(
        key: string,
        algorithm: CryptoSignatureAlgorithm,
        propertyName = "publicKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkSerializedBuffer(
            key,
            this.PUBLIC_KEY_MIN_BYTES,
            this.PUBLIC_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkSignaturePublicKeyAsBuffer(
        buffer: CoreBuffer,
        algorithm: CryptoSignatureAlgorithm,
        propertyName = "publicKey",
        throwError = true
    ): CryptoError | undefined {
        return super.checkBuffer(
            buffer,
            this.PUBLIC_KEY_MIN_BYTES,
            this.PUBLIC_KEY_MAX_BYTES,
            propertyName,
            throwError
        );
    }

    public static checkSignaturePublicKey(
        publicKey: string | CoreBuffer,
        algorithm: CryptoSignatureAlgorithm,
        propertyName = "publicKey",
        throwError = true
    ): CryptoError | undefined {
        if (typeof publicKey === "string") {
            return this.checkSignaturePublicKeyAsString(publicKey, algorithm, propertyName, throwError);
        }

        return this.checkSignaturePublicKeyAsBuffer(publicKey, algorithm, propertyName, throwError);
    }

    public static checkSignatureAsString(signature: string, throwError = true): CryptoError | undefined {
        return this.checkSerializedBuffer(
            signature,
            this.SIGNATURE_MIN_BYTES,
            this.SIGNATURE_MAX_BYTES,
            "signature",
            throwError
        );
    }

    public static checkSignatureAsBuffer(signature: CoreBuffer, throwError = true): CryptoError | undefined {
        return this.checkBuffer(signature, this.SIGNATURE_MIN_BYTES, this.SIGNATURE_MAX_BYTES, "signature", throwError);
    }

    public static checkSignature(signature: string | CoreBuffer, throwError = true): CryptoError | undefined {
        if (typeof signature === "string") return this.checkSignatureAsString(signature, throwError);

        return this.checkSignatureAsBuffer(signature, throwError);
    }

    public static checkSignaturePublicKeyId(keyId: string, throwError = true): CryptoError | undefined {
        return this.checkId(keyId, 0, 30, throwError);
    }

    public static checkSignatureKeyId(keyId: string, throwError = true): CryptoError | undefined {
        let error;
        if (typeof keyId === "undefined") {
            return;
        }
        if (typeof keyId !== "string") {
            error = new CryptoError(CryptoErrorCode.WrongId, "KeyId must be of type string!");
        }
        if (!error && keyId.length > 50) {
            error = new CryptoError(CryptoErrorCode.WrongId, "KeyId must be less than 50 characters.");
        }
        if (error && throwError) throw error;
        return error;
    }

    public static checkSignatureId(id: string, throwError = true): CryptoError | undefined {
        let error;
        if (typeof id === "undefined") {
            return;
        }
        if (typeof id !== "string") {
            error = new CryptoError(CryptoErrorCode.WrongId, "Signature id must be of type string!");
        }
        if (!error && id.length > 50) {
            error = new CryptoError(CryptoErrorCode.WrongId, "Signature id must be less than 50 characters.");
        }
        if (error && throwError) throw error;
        return error;
    }
}
