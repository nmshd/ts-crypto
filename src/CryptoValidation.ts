import { CoreBuffer } from "./CoreBuffer";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "./encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "./hash/CryptoHash";
import { CryptoStateType } from "./state/CryptoStateType";

export class CryptoValidation {
    public static checkObject(value: any, propertyName?: string, throwError = true): CryptoError | undefined {
        let error;
        if (!(typeof value === "object")) {
            let message;
            if (propertyName) {
                message = `Property ${propertyName} must be an object.`;
            } else {
                message = "Parameter must be an object.";
            }
            error = new CryptoError(CryptoErrorCode.WrongObject, message);
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkBufferAsStringOrBuffer(
        buffer: CoreBuffer | string,
        minBytes = 0,
        maxBytes: number = Number.MAX_SAFE_INTEGER,
        propertyName?: string,
        throwError = true
    ): CryptoError | undefined {
        if (typeof buffer === "string") {
            return this.checkSerializedBuffer(buffer, minBytes, maxBytes, propertyName, throwError);
        }

        return this.checkBuffer(buffer, minBytes, maxBytes, propertyName, throwError);
    }

    public static checkBuffer(
        buffer: CoreBuffer,
        minBytes = 0,
        maxBytes: number = Number.MAX_SAFE_INTEGER,
        propertyName?: string,
        throwError = true
    ): CryptoError | undefined {
        let error;
        if (buffer instanceof CoreBuffer) {
            if (buffer.buffer.byteLength < minBytes) {
                error = new CryptoError(CryptoErrorCode.WrongBuffer, `Buffer has a minimum of ${minBytes} bytes.`);
            } else if (buffer.buffer.byteLength > maxBytes) {
                error = new CryptoError(CryptoErrorCode.WrongBuffer, `Buffer has a maximum of ${maxBytes} bytes.`);
            }
        } else {
            error = new CryptoError(CryptoErrorCode.WrongBuffer, "Buffer must be of instance CoreBuffer.");
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkSerializedBuffer(
        serializedBuffer: string,
        minBytes = 0,
        maxBytes: number = Number.MAX_SAFE_INTEGER,
        propertyName?: string,
        throwError = true
    ): CryptoError | undefined {
        let error;
        if (typeof serializedBuffer !== "string") {
            error = new CryptoError(
                CryptoErrorCode.WrongSerializedBuffer,
                `Property ${propertyName} must be a string.`
            );
        }

        if (!error) {
            const byteLength = Math.floor(3 * (serializedBuffer.length / 4));

            if (byteLength < minBytes) {
                error = new CryptoError(
                    CryptoErrorCode.WrongSerializedBuffer,
                    `Size of serialized buffer within property ${propertyName} is smaller than the minimum of ${minBytes} bytes.`
                );
            }

            if (byteLength > maxBytes) {
                error = new CryptoError(
                    CryptoErrorCode.WrongSerializedBuffer,
                    `Size of serialized buffer within property ${propertyName} is greater than the maximum of ${maxBytes} bytes.`
                );
            }
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkEncryptionAlgorithm(algorithm: number, throwError = true): CryptoError | undefined {
        let error;

        switch (algorithm) {
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                break;
            default:
                error = new CryptoError(
                    CryptoErrorCode.EncryptionWrongAlgorithm,
                    "Encryption algorithm is not supported."
                );
                break;
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkHashAlgorithm(algorithm: number, throwError = true): CryptoError | undefined {
        let error;

        switch (algorithm) {
            case CryptoHashAlgorithm.BLAKE2B:
            case CryptoHashAlgorithm.SHA256:
            case CryptoHashAlgorithm.SHA512:
                break;
            default:
                error = new CryptoError(CryptoErrorCode.WrongHashAlgorithm, "Hash algorithm is not supported.");
                break;
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkStateType(type?: number, throwError = true): CryptoError | undefined {
        switch (type) {
            case CryptoStateType.Receive:
            case CryptoStateType.Transmit:
                return;
            default:
                const error = new CryptoError(CryptoErrorCode.StateWrongType, "State type is not supported.");
                if (throwError) throw error;
                else return error;
        }
    }

    public static checkId(id: string, minLength = 0, maxLength = 30, throwError = true): CryptoError | undefined {
        let error;

        if (typeof id === "undefined") return;

        if (typeof id !== "string") {
            error = new CryptoError(CryptoErrorCode.WrongId, "Id must be a string");
        }

        if ((!error && id.length < minLength) || id.length > maxLength) {
            error = new CryptoError(CryptoErrorCode.WrongId, "Id must be more than 0 and less than 101 characters.");
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkSerializedSecretKeyForAlgorithm(
        key: string,
        algorithm: CryptoEncryptionAlgorithm,
        throwError = true
    ): CryptoError | undefined {
        let error;
        if (typeof key !== "string") {
            error = new CryptoError(
                CryptoErrorCode.EncryptionWrongSecretKey,
                "Serialized SecretKey must be of type string."
            );
        } else {
            const byteLength = Math.floor(3 * (key.length / 4));

            let errorLength = 0;
            switch (algorithm) {
                case CryptoEncryptionAlgorithm.AES128_GCM:
                    if (byteLength !== 16) {
                        errorLength = 16;
                    }
                    break;
                case CryptoEncryptionAlgorithm.AES256_GCM:
                case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                    if (byteLength !== 32) {
                        errorLength = 32;
                    }
                    break;
                default:
                    error = new CryptoError(
                        CryptoErrorCode.EncryptionWrongAlgorithm,
                        "Encryption algorithm is not supported."
                    );
                    break;
            }
            if (!error && errorLength) {
                error = new CryptoError(
                    CryptoErrorCode.EncryptionWrongSecretKey,
                    `SecretKey must be ${errorLength} bytes long for encryption algorithm ${algorithm} (is ${byteLength})`
                );
            }
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkSecretKeyForAlgorithm(
        key?: CoreBuffer | string,
        algorithm?: CryptoEncryptionAlgorithm,
        throwError = true
    ): CryptoError | undefined {
        if (typeof key === "string") key = CoreBuffer.from(key);

        let error;
        let buffer: Uint8Array;
        if (key instanceof CoreBuffer) {
            buffer = key.buffer;

            let errorLength = 0;
            switch (algorithm) {
                case CryptoEncryptionAlgorithm.AES128_GCM:
                    if (buffer.byteLength !== 16) {
                        errorLength = 16;
                    }
                    break;
                case CryptoEncryptionAlgorithm.AES256_GCM:
                case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                    if (buffer.byteLength !== 32) {
                        errorLength = 32;
                    }
                    break;
                default:
                    error = new CryptoError(
                        CryptoErrorCode.EncryptionWrongAlgorithm,
                        "Encryption algorithm is not supported."
                    );
                    break;
            }
            if (!error && errorLength) {
                error = new CryptoError(
                    CryptoErrorCode.EncryptionWrongSecretKey,
                    `SecretKey must be ${errorLength} bytes long for encryption algorithm ${algorithm}`
                );
            }
        } else {
            error = new CryptoError(CryptoErrorCode.EncryptionWrongSecretKey, "SecretKey must be of type CoreBuffer.");
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkNonceAsString(
        nonce: string,
        algorithm: CryptoEncryptionAlgorithm,
        propertyName = "nonce",
        throwError = true
    ): CryptoError | undefined {
        return this.checkSerializedBuffer(nonce, 12, 24, propertyName, throwError);
    }

    public static checkNonceAsBuffer(
        nonce: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm,
        propertyName = "nonce",
        throwError = true
    ): CryptoError | undefined {
        return this.checkBuffer(nonce, 12, 24, propertyName, throwError);
    }

    public static checkNonce(
        nonce: string | CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm,
        propertyName = "nonce",
        throwError = true
    ): CryptoError | undefined {
        if (typeof nonce === "string") return this.checkNonceAsString(nonce, algorithm, propertyName, throwError);

        return this.checkNonceAsBuffer(nonce, algorithm, propertyName, throwError);
    }

    public static checkNonceForAlgorithm(
        nonce: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm,
        throwError = true
    ): CryptoError | undefined {
        let error;
        let buffer: Uint8Array;
        if (nonce instanceof CoreBuffer) {
            buffer = nonce.buffer;
            let errorLength = 0;
            switch (algorithm) {
                case CryptoEncryptionAlgorithm.AES128_GCM:
                case CryptoEncryptionAlgorithm.AES256_GCM:
                    if (buffer.byteLength !== 12) {
                        errorLength = 12;
                    }
                    break;
                case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                    if (buffer.byteLength !== 24) {
                        errorLength = 24;
                    }
                    break;
                default:
                    error = new CryptoError(
                        CryptoErrorCode.EncryptionWrongAlgorithm,
                        "Encryption algorithm is not supported."
                    );
                    break;
            }
            if (!error && errorLength) {
                error = new CryptoError(
                    CryptoErrorCode.EncryptionWrongNonce,
                    `Nonce must be ${errorLength} bytes long for encryption algorithm ${algorithm}`
                );
            }
        } else {
            error = new CryptoError(CryptoErrorCode.EncryptionWrongNonce, "Nonce must be of type CoreBuffer.");
        }

        if (error && throwError) throw error;
        return error;
    }

    public static checkCounter(counter?: number, throwError = true): CryptoError | undefined {
        let error;
        if (typeof counter !== "number" || counter < 0 || counter > 4294967295) {
            error = new CryptoError(
                CryptoErrorCode.EncryptionWrongCounter,
                `Counter must be a positive integer within 0 and ${Number.MAX_SAFE_INTEGER}.`
            );
        }

        if (error && throwError) throw error;
        return error;
    }
}
