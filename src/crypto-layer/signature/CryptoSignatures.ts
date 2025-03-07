import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoSignature } from "src/signature/CryptoSignature";
import { CryptoSignatureValidation } from "src/signature/CryptoSignatureValidation";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";
import { cryptoHashFromCryptoHashAlgorithm, CryptoLayerUtils } from "../CryptoLayerUtils";
import { CryptoSignatureKeypairHandle } from "./CryptoSignatureKeypair";
import { CryptoSignaturePrivateKeyHandle } from "./CryptoSignaturePrivateKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "./CryptoSignaturePublicKeyHandle";

/**
 * Provides cryptographic signature functionalities using the crypto layer.
 * This class leverages an underlying crypto provider to generate keypairs,
 * sign content, and verify signatures.
 */
export class CryptoSignaturesWithCryptoLayer {
    /**
     * Asynchronously converts a private key handle into its corresponding public key handle.
     *
     * @param privateKey - The {@link CryptoSignaturePrivateKeyHandle} to convert.
     * @returns A Promise that resolves to a {@link CryptoSignaturePublicKeyHandle}.
     */
    public static async privateKeyToPublicKey(
        privateKey: CryptoSignaturePrivateKeyHandle
    ): Promise<CryptoSignaturePublicKeyHandle> {
        return await privateKey.toPublicKey();
    }

    /**
     * Generates a signature keypair for the specified elliptic algorithm.
     *
     * @param providerIdent - The identifier for the crypto provider to use.
     * @param spec - The specification/configuration for the keypair.
     * @returns A Promise that resolves to a {@link CryptoSignatureKeypairHandle} containing the generated keypair.
     */
    public static async generateKeypair(
        providerIdent: ProviderIdentifier,
        spec: KeyPairSpec
    ): Promise<CryptoSignatureKeypairHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const rawKeyPairHandle = await provider.createKeyPair(spec);
        const privateKey = await CryptoSignaturePrivateKeyHandle.newFromProviderAndKeyPairHandle(
            provider,
            rawKeyPairHandle
        );
        const publicKey = await privateKey.toPublicKey();
        return CryptoSignatureKeypairHandle.fromPublicAndPrivateKeys(publicKey, privateKey);
    }

    /**
     * Signs the given content using the provided private key handle.
     *
     * @param content - The {@link CoreBuffer} containing the data to be signed.
     * @param privateKey - The {@link CryptoSignaturePrivateKeyHandle} to use for signing.
     * @param id - Optional identifier for the signature.
     * @returns A Promise that resolves to a {@link CryptoSignature} representing the signature.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.SignatureSign} if signing fails.
     */
    public static async sign(
        content: CoreBuffer,
        privateKey: CryptoSignaturePrivateKeyHandle,
        id?: string
    ): Promise<CryptoSignature> {
        CryptoSignatureValidation.checkBuffer(content, 1);

        try {
            const signatureArray = await privateKey.keyPairHandle.signData(content.buffer);
            const algorithm = CryptoLayerUtils.getHashAlgorithm(privateKey);
            const keyId = privateKey.id;

            const signatureBuffer: CoreBuffer = new CoreBuffer(signatureArray);
            const signature = CryptoSignature.from({ signature: signatureBuffer, algorithm, keyId, id });
            return signature;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.SignatureSign, `${e}`);
        }
    }

    /**
     * Verifies a signature against the provided content using the specified public key handle.
     *
     * @param content - The {@link CoreBuffer} containing the data whose signature is to be verified.
     * @param signature - The {@link CryptoSignature} to verify.
     * @param publicKey - The {@link CryptoSignaturePublicKeyHandle} corresponding to the signing key.
     * @returns A Promise that resolves to a boolean indicating whether the signature is valid.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.SignatureWrongAlgorithm} if the signature algorithm does not match the public key's algorithm.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.SignatureVerify} if verification fails.
     */
    public static async verify(
        content: CoreBuffer,
        signature: CryptoSignature,
        publicKey: CryptoSignaturePublicKeyHandle
    ): Promise<boolean> {
        CryptoSignatureValidation.checkBuffer(content, 1);

        if (cryptoHashFromCryptoHashAlgorithm(signature.algorithm) !== publicKey.spec.signing_hash) {
            throw new CryptoError(
                CryptoErrorCode.SignatureWrongAlgorithm,
                `Algorithm ${signature.algorithm} != the algorithm the public key was initialized with.`
            );
        }

        try {
            return await publicKey.keyPairHandle.verifySignature(content.buffer, signature.signature.buffer);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.SignatureVerify, `${e}`);
        }
    }
}
