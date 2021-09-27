import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoSignaturePrivateKey } from "./CryptoSignaturePrivateKey";
import { CryptoSignaturePublicKey } from "./CryptoSignaturePublicKey";
import { CryptoSignatureAlgorithm } from "./CryptoSignatures";

export class CryptoSignatureValidation extends CryptoValidation {
    public static readonly PRIVATE_KEY_MIN_BYTES: number = 20;
    public static readonly PRIVATE_KEY_MAX_BYTES: number = 80;
    public static readonly PUBLIC_KEY_MIN_BYTES: number = 20;
    public static readonly PUBLIC_KEY_MAX_BYTES: number = 80;
    public static readonly SIGNATURE_MIN_BYTES: number = 20;
    public static readonly SIGNATURE_MAX_BYTES: number = 100;

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
        privateKey: CryptoSignaturePrivateKey,
        throwError = true
    ): CryptoError | undefined {
        let error;
        if (!(privateKey instanceof CryptoSignaturePrivateKey)) {
            error = new CryptoError(
                CryptoErrorCode.SignatureWrongPrivateKey,
                "PrivateKey must be of type CryptoSignaturePrivateKey."
            );
        }

        if (error && throwError) throw error;
        return error;
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
        publicKey: CryptoSignaturePublicKey,
        throwError = true
    ): CryptoError | undefined {
        let error;
        if (!(publicKey instanceof CryptoSignaturePublicKey)) {
            error = new CryptoError(
                CryptoErrorCode.SignatureWrongPublicKey,
                "Public key must be of type CryptoSignaturePublicKey."
            );
        }

        if (error && throwError) throw error;
        return error;
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

    public static checkSignatureKeypair(
        privateKey: CryptoSignaturePrivateKey,
        publicKey: CryptoSignaturePublicKey,
        throwError = true
    ): CryptoError | undefined {
        let error;

        error = this.checkSignaturePublicKey(publicKey, throwError);
        if (error && throwError) throw error;
        else if (error) return error;

        error = this.checkSignaturePrivateKey(privateKey, throwError);
        if (error && throwError) throw error;
        else if (error) return error;

        if (privateKey.algorithm !== publicKey.algorithm) {
            error = new CryptoError(
                CryptoErrorCode.SignatureWrongAlgorithm,
                "Algorithms of private and public key do not match."
            );
        }

        if (error && throwError) throw error;
        return error;
    }
}
