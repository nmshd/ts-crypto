import { serialize, type, validate } from "@js-soft/ts-serval";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoSignature } from "../../signature/CryptoSignature";
import { getProvider } from "../CryptoLayerProviders";
import { CryptoEncryptionWithCryptoLayer } from "../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
import { CryptoExchangeWithCryptoLayer } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "../exchange/CryptoExchangePublicKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "../signature/CryptoSignaturePublicKeyHandle";
import { CryptoSignaturesWithCryptoLayer } from "../signature/CryptoSignatures";
import { CryptoRelationshipPublicRequestHandle } from "./CryptoRelationshipPublicRequestHandle";

/**
 * Represents a handle-based implementation of relationship request secrets.
 */
@type("CryptoRelationshipRequestSecretsHandle")
export class CryptoRelationshipRequestSecretsHandle {
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public exchangeKeypair: CryptoExchangeKeypairHandle;

    @validate()
    @serialize()
    public ephemeralKeypair: CryptoExchangeKeypairHandle;

    @validate()
    @serialize()
    public signatureKeypair: CryptoExchangeKeypairHandle;

    @validate()
    @serialize()
    public peerIdentityKey: CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize()
    public peerExchangeKey: CryptoExchangePublicKeyHandle;

    @validate()
    @serialize()
    public secretKey: CryptoSecretKeyHandle;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    /**
     * Creates request secrets from peer public keys (handle-based).
     */
    public static async fromPeer(
        providerName: string,
        peerExchangeKey: CryptoExchangePublicKeyHandle,
        peerIdentityKey: CryptoSignaturePublicKeyHandle
    ): Promise<CryptoRelationshipRequestSecretsHandle> {
        // Generate keypairs and nonce
        const [exchangeKeypair, ephemeralKeypair, signatureKeypair, nonce] = await Promise.all([
            CryptoExchangeWithCryptoLayer.generateKeypair({ providerName }, peerExchangeKey.spec),
            CryptoExchangeWithCryptoLayer.generateKeypair({ providerName }, peerExchangeKey.spec),
            CryptoSignaturesWithCryptoLayer.generateKeypair({ providerName }, peerIdentityKey.spec),
            CoreBuffer.random(24)
        ]);

        // Get the provider
        const provider = getProvider({ providerName });
        if (!provider) {
            throw new Error(`Provider ${providerName} not found`);
        }

        // Derive the master key
        const masterKey = await CryptoExchangeWithCryptoLayer.deriveRequestor(ephemeralKeypair, peerExchangeKey);

        // Create a key spec for the derived key
        const keySpec: KeySpec = {
            cipher: "XChaCha20Poly1305",
            signing_hash: "Sha2_256",
            ephemeral: true
        };

        // Derive the secret key using the provider, following the same pattern as libsodium implementation
        const secretKey = await provider.deriveKeyFromBase(
            masterKey.receivingKey.buffer, // Using receivingKey as base, matching libsodium implementation
            1, // Using 1 as keyId, matching the original
            "REQTMP01", // Using the same context as the original
            keySpec // Providing the key spec required by the CAL interface
        );

        const secretKeyNew = await CryptoSecretKeyHandle.importRawKeyIntoHandle(
            { providerName },
            CoreBuffer.from(await secretKey.extractKey()),
            await secretKey.spec(),
            masterKey.algorithm
        );

        // Create and return the secrets
        const secrets = new CryptoRelationshipRequestSecretsHandle();
        secrets.exchangeKeypair = exchangeKeypair;
        secrets.ephemeralKeypair = ephemeralKeypair;
        secrets.signatureKeypair = signatureKeypair;
        secrets.peerExchangeKey = peerExchangeKey;
        secrets.peerIdentityKey = peerIdentityKey;
        secrets.secretKey = secretKeyNew;
        secrets.nonce = nonce;

        return secrets;
    }

    /** Signs content with the private signature key. */
    public async sign(content: CoreBuffer): Promise<CryptoSignature> {
        return await CryptoSignaturesWithCryptoLayer.sign(content, this.signatureKeypair.privateKey);
    }

    /** Verifies content with the public key of the own signature keypair. */
    public async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.signatureKeypair.publicKey);
    }

    /** Verifies content with the peer’s identity public key. */
    public async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.peerIdentityKey);
    }

    /** Encrypts request content using the handle-based secret key. */
    public async encryptRequest(content: CoreBuffer): Promise<CryptoCipher> {
        return await CryptoEncryptionWithCryptoLayer.encrypt(content, this.secretKey);
    }

    /** Decrypts request content using the handle-based secret key. */
    public async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        return await CryptoEncryptionWithCryptoLayer.decrypt(cipher, this.secretKey);
    }

    /** Converts secrets to a public request handle. */
    public toPublicRequest(): CryptoRelationshipPublicRequestHandle {
        const requestHandle = new CryptoRelationshipPublicRequestHandle();
        requestHandle.id = this.id;
        requestHandle.exchangeKey = this.exchangeKeypair.publicKey;
        requestHandle.signatureKey = this.signatureKeypair.publicKey;
        requestHandle.ephemeralKey = this.ephemeralKeypair.publicKey;
        requestHandle.nonce = this.nonce;
        return requestHandle;
    }
}
