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

export class CryptoSignaturesWithCryptoLayer {
    public static async privateKeyToPublicKey(
        privateKey: CryptoSignaturePrivateKeyHandle
    ): Promise<CryptoSignaturePublicKeyHandle> {
        return await privateKey.toPublicKey();
    }

    /**
     * Generates a keypair for the specified elliptic algorithm
     * @param algorithm
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
