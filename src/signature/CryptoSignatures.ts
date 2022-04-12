import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoSignature } from "./CryptoSignature";
import { CryptoSignatureAlgorithm } from "./CryptoSignatureAlgorithm";
import { CryptoSignatureKeypair } from "./CryptoSignatureKeypair";
import { CryptoSignaturePrivateKey } from "./CryptoSignaturePrivateKey";
import { CryptoSignaturePublicKey } from "./CryptoSignaturePublicKey";
import { CryptoSignatureValidation } from "./CryptoSignatureValidation";

export class CryptoSignatures {
    public static async privateKeyToPublicKey(
        privateKey: CryptoSignaturePrivateKey
    ): Promise<CryptoSignaturePublicKey> {
        switch (privateKey.algorithm) {
            case CryptoSignatureAlgorithm.ECDSA_ED25519:
                try {
                    const publicKey = (await SodiumWrapper.ready()).crypto_sign_ed25519_sk_to_pk(
                        privateKey.privateKey.buffer
                    );
                    return CryptoSignaturePublicKey.from({
                        algorithm: privateKey.algorithm,
                        publicKey: CoreBuffer.from(publicKey)
                    });
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.SignatureKeyGeneration, `${e}`);
                }
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }
    }

    /**
     * Generates a keypair for the specified elliptic algorithm
     * @param algorithm
     */
    public static async generateKeypair(
        algorithm: CryptoSignatureAlgorithm = CryptoSignatureAlgorithm.ECDSA_ED25519
    ): Promise<CryptoSignatureKeypair> {
        CryptoSignatureValidation.checkSignatureAlgorithm(algorithm);

        let pair;
        switch (algorithm) {
            case CryptoSignatureAlgorithm.ECDSA_ED25519:
                try {
                    pair = (await SodiumWrapper.ready()).crypto_sign_keypair();
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.SignatureKeyGeneration, `${e}`);
                }
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }

        const privateKey = CryptoSignaturePrivateKey.from({ algorithm, privateKey: CoreBuffer.from(pair.privateKey) });
        const publicKey = CryptoSignaturePublicKey.from({ algorithm, publicKey: CoreBuffer.from(pair.publicKey) });

        const keypair = CryptoSignatureKeypair.from({ publicKey, privateKey });
        return keypair;
    }

    public static async sign(
        content: CoreBuffer,
        privateKey: CryptoSignaturePrivateKey | CoreBuffer,
        algorithm: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA512,
        keyId?: string,
        id?: string
    ): Promise<CryptoSignature> {
        CryptoSignatureValidation.checkBuffer(content, 1);
        CryptoSignatureValidation.checkHashAlgorithm(algorithm);

        const privateKeyBuffer = this.getArrayOfPrivateKey(privateKey);

        try {
            const signatureArray = (await SodiumWrapper.ready()).crypto_sign_detached(content.buffer, privateKeyBuffer);

            const signatureBuffer: CoreBuffer = new CoreBuffer(signatureArray);
            const signature = CryptoSignature.from({ signature: signatureBuffer, algorithm, keyId, id });
            return signature;
        } catch (e) {
            const error = new CryptoError(CryptoErrorCode.SignatureSign, `${e}`);
            throw error;
        }
    }

    private static getArrayOfPrivateKey(privateKey: CryptoSignaturePrivateKey | CoreBuffer): Uint8Array {
        let buffer: CoreBuffer;
        if (privateKey instanceof CryptoSignaturePrivateKey) {
            buffer = privateKey.privateKey;
        } else if (privateKey instanceof CoreBuffer) {
            buffer = privateKey;
        } else {
            throw new CryptoError(
                CryptoErrorCode.SignatureWrongPrivateKey,
                "The given private key must be of type CryptoSignaturePrivateKey or CoreBuffer."
            );
        }
        CryptoSignatureValidation.checkBuffer(buffer);

        return buffer.buffer;
    }

    public static async verify(
        content: CoreBuffer,
        signature: CryptoSignature,
        publicKey: CryptoSignaturePublicKey | CoreBuffer
    ): Promise<boolean> {
        CryptoSignatureValidation.checkBuffer(content, 1);

        const publicKeyBuffer = this.getArrayOfPublicKey(publicKey);

        try {
            const valid = (await SodiumWrapper.ready()).crypto_sign_verify_detached(
                signature.signature.buffer,
                content.buffer,
                publicKeyBuffer
            );

            return valid;
        } catch (e) {
            const error = new CryptoError(CryptoErrorCode.SignatureVerify, `${e}`);
            throw error;
        }
    }

    private static getArrayOfPublicKey(publicKey: CryptoSignaturePublicKey | CoreBuffer): Uint8Array {
        let buffer: CoreBuffer;
        if (publicKey instanceof CryptoSignaturePublicKey) {
            buffer = publicKey.publicKey;
        } else if (publicKey instanceof CoreBuffer) {
            buffer = publicKey;
        } else {
            throw new CryptoError(
                CryptoErrorCode.SignatureWrongPublicKey,
                "The given public key must be of type CryptoSignaturePublicKey or CoreBuffer."
            );
        }
        CryptoSignatureValidation.checkBuffer(buffer);

        return buffer.buffer;
    }
}
