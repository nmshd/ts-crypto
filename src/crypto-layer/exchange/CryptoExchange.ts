import { DHExchange, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoExchangeSecrets } from "../../exchange/CryptoExchangeSecrets";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";
import { CryptoExchangeKeypairHandle } from "./CryptoExchangeKeypairHandle";
import { CryptoExchangePrivateKeyHandle } from "./CryptoExchangePrivateKeyHandle";
import { CryptoExchangePublicKeyHandle } from "./CryptoExchangePublicKeyHandle";

/**
 * Provides cryptographic key exchange functionalities using the crypto layer.
 * This class is designed to replace the libsodium-based implementation, leveraging
 * the Rust-based crypto layer for enhanced security and performance.
 */
export class CryptoExchangeWithCryptoLayer {
    /**
     * Asynchronously converts a private key handle for key exchange into its corresponding public key handle.
     *
     * @param privateKey - The {@link CryptoExchangePrivateKeyHandle} to convert.
     * @returns A Promise that resolves to a {@link CryptoExchangePublicKeyHandle}.
     */
    public static async privateKeyToPublicKey(
        privateKey: CryptoExchangePrivateKeyHandle
    ): Promise<CryptoExchangePublicKeyHandle> {
        return await privateKey.toPublicKey();
    }

    /**
     * Asynchronously generates a key pair for cryptographic key exchange using the crypto layer.
     *
     * @param providerIdent - Identifier for the crypto provider to be used for key generation.
     * @param spec - Specification for the key pair to be generated, including algorithm and security parameters.
     * @returns A Promise that resolves to a {@link CryptoExchangeKeypairHandle} containing the generated key pair handles.
     */
    public static async generateKeypair(
        providerIdent: ProviderIdentifier,
        spec: KeyPairSpec
    ): Promise<CryptoExchangeKeypairHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const rawKeyPairHandle = await provider.createKeyPair(spec);
        const privateKey = await CryptoExchangePrivateKeyHandle.newFromProviderAndKeyPairHandle(
            provider,
            rawKeyPairHandle
        );
        const publicKey = await privateKey.toPublicKey();
        return CryptoExchangeKeypairHandle.fromPublicAndPrivateKeys(publicKey, privateKey);
    }

    /**
     * Asynchronously starts an ephemeral Diffie-Hellman exchange.
     * This generates an internal ephemeral key pair within the returned DHExchange context.
     *
     * @param providerIdent - Identifier for the crypto provider to be used.
     * @param spec - Specification for the ephemeral key pair to be generated (algorithm, curve).
     * @returns A Promise that resolves to a {@link DHExchange} handle for the exchange context.
     */
    public static async generateDHExchange(providerIdent: ProviderIdentifier, spec: KeyPairSpec): Promise<DHExchange> {
        const provider = getProviderOrThrow(providerIdent);
        const dhHandle = await provider.startEphemeralDhExchange(spec);
        return dhHandle;
    }

    /**
     * Asynchronously derives shared secrets using an existing DHExchange context in the 'requestor' role.
     * Accepts the requestor's DHExchange handle and the templator's PublicKey handle.
     */
    public static async deriveRequestor(
        requestorDHHandle: DHExchange,
        templatorPublicKeyBytes: Uint8Array,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.AES256_GCM
    ): Promise<CryptoExchangeSecrets> {
        try {
            const [rx, tx] = await requestorDHHandle.deriveServerSessionKeys(templatorPublicKeyBytes); // Pass bytes here

            const secrets = CryptoExchangeSecrets.from({
                receivingKey: CoreBuffer.from(rx),
                transmissionKey: CoreBuffer.from(tx),
                algorithm: algorithm
            });

            return secrets;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
    }

    /**
     * Asynchronously derives shared secrets using an existing DHExchange context in the 'templator' role.
     * Accepts the templator's DHExchange handle and the requestor's PublicKey handle.
     */
    public static async deriveTemplator(
        templatorDHHandle: DHExchange,
        requestorPublicKeyBytes: Uint8Array,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.AES256_GCM
    ): Promise<CryptoExchangeSecrets> {
        try {
            const [rx, tx] = await templatorDHHandle.deriveClientSessionKeys(requestorPublicKeyBytes); // Pass bytes here

            const secrets = CryptoExchangeSecrets.from({
                receivingKey: CoreBuffer.from(rx),
                transmissionKey: CoreBuffer.from(tx),
                algorithm: algorithm
            });

            return secrets;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
    }
}
