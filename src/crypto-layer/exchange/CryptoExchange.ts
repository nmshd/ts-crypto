import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { defaults } from "lodash";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoExchangeAlgorithm } from "../../exchange/CryptoExchange";
import { CryptoExchangeSecrets } from "../../exchange/CryptoExchangeSecrets";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";
import { asymSpecFromCryptoAlgorithm, DEFAULT_KEY_PAIR_SPEC } from "../CryptoLayerUtils";
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

        return await CryptoExchangeKeypairHandle.from({ publicKey, privateKey });
    }

    private static createDHExchangeSpec(algorithm: CryptoExchangeAlgorithm): KeyPairSpec {
        return defaults(
            {
                asym_spec: asymSpecFromCryptoAlgorithm(algorithm),
                ephemeral: true,
                non_exportable: false
            },
            DEFAULT_KEY_PAIR_SPEC
        );
    }

    /**
     * Asynchronously derives shared secrets for key exchange in the 'requestor' role using the crypto layer.
     * This method is called by the entity initiating the key exchange (e.g., client).
     *
     * @param requestorKeypair - The {@link CryptoExchangeKeypairHandle} of the requestor.
     * @param templatorPublicKey - The {@link CryptoExchangePublicKeyHandle} of the templator (counterparty).
     * @param algorithm - The {@link CryptoEncryptionAlgorithm} to be used for the derived secrets. Defaults to XCHACHA20_POLY1305.
     * @returns A Promise that resolves to a {@link CryptoExchangeSecrets} object containing the derived transmission and receiving keys.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.ExchangeWrongAlgorithm} if the key exchange algorithm is not supported.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.ExchangeKeyDerivation} if key derivation fails.
     */
    public static async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypairHandle,
        templatorPublicKey: CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        const exchangeAlgorithm = requestorKeypair.privateKey.spec.asym_spec;

        if (asymSpecFromCryptoAlgorithm(CryptoExchangeAlgorithm.ECDH_X25519) !== exchangeAlgorithm) {
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                `Algorithm ${exchangeAlgorithm} != the algorithm the private key was initialized with.`
            );
        }
        if (templatorPublicKey.spec.asym_spec !== exchangeAlgorithm) {
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                `Algorithm of public key ${templatorPublicKey.spec.asym_spec} does not match algorithm of private key ${exchangeAlgorithm}.`
            );
        }

        try {
            const provider = getProviderOrThrow({
                providerName: requestorKeypair.privateKey.providerName
            });
            const dhExchangeSpec: KeyPairSpec = CryptoExchangeWithCryptoLayer.createDHExchangeSpec(
                CryptoExchangeAlgorithm.ECDH_X25519
            );

            const dhExchange = await provider.startEphemeralDhExchange(dhExchangeSpec);

            // Use deriveServerSessionKeys for the requestor (server role)
            const [sharedRx, sharedTx] = await dhExchange.deriveServerSessionKeys(
                await templatorPublicKey.keyPairHandle.getPublicKey()
            );

            const secrets = CryptoExchangeSecrets.from({
                receivingKey: CoreBuffer.from(sharedRx),
                transmissionKey: CoreBuffer.from(sharedTx),
                algorithm: algorithm
            });
            return secrets;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
    }

    /**
     * Asynchronously derives shared secrets for key exchange in the 'templator' role using the crypto layer.
     * This method is called by the entity responding to the key exchange request (e.g., server).
     *
     * @param templatorKeypair - The {@link CryptoExchangeKeypairHandle} of the templator.
     * @param requestorPublicKey - The {@link CryptoExchangePublicKeyHandle} of the requestor (counterparty).
     * @param algorithm - The {@link CryptoEncryptionAlgorithm} to be used for the derived secrets. Defaults to XCHACHA20_POLY1305.
     * @returns A Promise that resolves to a {@link CryptoExchangeSecrets} object containing the derived transmission and receiving keys.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.ExchangeWrongAlgorithm} if the key exchange algorithm is not supported or mismatched.
     * @throws {@link CryptoError} with {@link CryptoErrorCode.ExchangeKeyDerivation} if key derivation fails.
     */
    public static async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypairHandle,
        requestorPublicKey: CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        const exchangeAlgorithm = templatorKeypair.privateKey.spec.asym_spec;

        if (asymSpecFromCryptoAlgorithm(CryptoExchangeAlgorithm.ECDH_X25519) !== exchangeAlgorithm) {
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                `Algorithm ${exchangeAlgorithm} != the algorithm the private key was initialized with.`
            );
        }
        if (requestorPublicKey.spec.asym_spec !== exchangeAlgorithm) {
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                `Algorithm of public key ${requestorPublicKey.spec.asym_spec} does not match algorithm of private key ${exchangeAlgorithm}.`
            );
        }

        try {
            const provider = getProviderOrThrow({
                providerName: templatorKeypair.privateKey.providerName
            });
            const dhExchangeSpec: KeyPairSpec = CryptoExchangeWithCryptoLayer.createDHExchangeSpec(
                CryptoExchangeAlgorithm.ECDH_X25519
            );

            const dhExchange = await provider.startEphemeralDhExchange(dhExchangeSpec);

            // Use deriveClientSessionKeys for the templator (client role)
            const [sharedRx, sharedTx] = await dhExchange.deriveClientSessionKeys(
                await requestorPublicKey.keyPairHandle.getPublicKey()
            );

            const secrets = CryptoExchangeSecrets.from({
                receivingKey: CoreBuffer.from(sharedRx),
                transmissionKey: CoreBuffer.from(sharedTx),
                algorithm: algorithm
            });
            return secrets;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
    }
}
