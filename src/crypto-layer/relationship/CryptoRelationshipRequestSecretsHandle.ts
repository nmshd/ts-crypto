import { serialize, type, validate } from "@js-soft/ts-serval";
import { DHExchange, KeyPairSpec, KeySpec, Provider, KeyHandle as ProviderKeyHandle } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoExchangeSecrets } from "../../exchange/CryptoExchangeSecrets";
import { CryptoSignature } from "../../signature/CryptoSignature";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";
import { CryptoEncryptionWithCryptoLayer } from "../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
import { CryptoExchangeWithCryptoLayer } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "../exchange/CryptoExchangePublicKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "../signature/CryptoSignaturePublicKeyHandle";
import { CryptoSignaturesWithCryptoLayer } from "../signature/CryptoSignatures";
import { CryptoRelationshipPublicRequestHandle } from "./CryptoRelationshipPublicRequestHandle";

/**
 * Represents relationship request secrets, managing keys and derivation.
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
    public signatureKeypair: CryptoExchangeKeypairHandle;

    @validate()
    @serialize()
    public ephemeralPublicKey: CryptoExchangePublicKeyHandle;

    // Peer keys
    @validate()
    @serialize()
    public peerIdentityKey: CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize()
    public peerExchangeKey: CryptoExchangePublicKeyHandle;

    // Derived secret
    @validate()
    @serialize()
    public secretKey: CryptoSecretKeyHandle;

    // Nonce
    @validate()
    @serialize()
    public nonce: CoreBuffer;

    /**
     * Creates request secrets from peer public keys.
     */
    public static async fromPeer(
        providerIdent: ProviderIdentifier,
        peerExchangeKey: CryptoExchangePublicKeyHandle,
        peerIdentityKey: CryptoSignaturePublicKeyHandle
    ): Promise<CryptoRelationshipRequestSecretsHandle> {
        const provider: Provider = getProviderOrThrow(providerIdent);

        const [exchangeKeypair, signatureKeypair, nonce] = await Promise.all([
            CryptoExchangeWithCryptoLayer.generateKeypair(providerIdent, peerExchangeKey.spec),
            CryptoSignaturesWithCryptoLayer.generateKeypair(providerIdent, peerIdentityKey.spec),
            CoreBuffer.random(24)
        ]);

        const ephemeralSpec: KeyPairSpec = { ...peerExchangeKey.spec, ephemeral: true };

        // 1. Generate ephemeral DH context
        const ephemeralDHHandle: DHExchange = await CryptoExchangeWithCryptoLayer.generateDHExchange(
            providerIdent,
            ephemeralSpec
        );

        // 2. Get ephemeral public key bytes
        const ephemeralPublicKeyBytes: Uint8Array = await ephemeralDHHandle.getPublicKey();

        // 3. Create the ephemeral public key handle
        const ephemeralPublicKeyHandle = await CryptoExchangePublicKeyHandle.fromBytes(
            provider,
            ephemeralPublicKeyBytes,
            ephemeralSpec
        );

        // 4. Derive secrets using DH context and peer key bytes
        const peerExchangeKeyBytes = await peerExchangeKey.keyPairHandle.getPublicKey();
        const masterKey: CryptoExchangeSecrets = await CryptoExchangeWithCryptoLayer.deriveRequestor(
            ephemeralDHHandle,
            peerExchangeKeyBytes
        );

        // 5. Derive final secret key
        const derivedKeySpec: KeySpec = {
            cipher: "XChaCha20Poly1305",
            // eslint-disable-next-line @typescript-eslint/naming-convention
            signing_hash: "Sha2_256",
            ephemeral: true
        };
        const derivedKeyHandle: ProviderKeyHandle = await provider.deriveKeyFromBase(
            masterKey.receivingKey.buffer,
            1,
            "REQTMP01",
            derivedKeySpec
        );

        // 6. Wrap derived secret key into app-level handle
        let finalSecretKeyHandle: CryptoSecretKeyHandle;
        try {
            const derivedKeyBytes = await derivedKeyHandle.extractKey();
            const derivedKeySpecFromHandle = await derivedKeyHandle.spec();
            finalSecretKeyHandle = await CryptoSecretKeyHandle.importRawKeyIntoHandle(
                providerIdent,
                CoreBuffer.from(derivedKeyBytes),
                derivedKeySpecFromHandle,
                masterKey.algorithm
            );
        } catch (e) {
            throw new Error(`Failed to handle derived secret key: ${e instanceof Error ? e.message : String(e)}`);
        }

        // 7. Construct the final secrets object
        const secrets = new CryptoRelationshipRequestSecretsHandle();
        secrets.id = undefined;
        secrets.exchangeKeypair = exchangeKeypair;
        secrets.signatureKeypair = signatureKeypair;
        secrets.ephemeralPublicKey = ephemeralPublicKeyHandle;
        secrets.peerExchangeKey = peerExchangeKey;
        secrets.peerIdentityKey = peerIdentityKey;
        secrets.secretKey = finalSecretKeyHandle;
        secrets.nonce = nonce;

        return secrets;
    }

    public async sign(content: CoreBuffer): Promise<CryptoSignature> {
        return await CryptoSignaturesWithCryptoLayer.sign(content, this.signatureKeypair.privateKey as any);
    }

    public async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.signatureKeypair.publicKey as any);
    }

    public async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.peerIdentityKey);
    }

    public async encryptRequest(content: CoreBuffer): Promise<CryptoCipher> {
        return await CryptoEncryptionWithCryptoLayer.encrypt(content, this.secretKey);
    }

    public async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        return await CryptoEncryptionWithCryptoLayer.decrypt(cipher, this.secretKey);
    }

    /**
     * Creates a public handle containing only the public keys and nonce.
     * Uses the directly stored ephemeral public key handle.
     * @returns A {@link CryptoRelationshipPublicRequestHandle} instance.
     */
    public toPublicRequest(): CryptoRelationshipPublicRequestHandle {
        const requestHandle = new CryptoRelationshipPublicRequestHandle();
        requestHandle.id = this.id;
        requestHandle.exchangeKey = this.exchangeKeypair.publicKey;
        requestHandle.signatureKey = this.signatureKeypair.publicKey as any;
        requestHandle.ephemeralKey = this.ephemeralPublicKey;
        requestHandle.nonce = this.nonce;
        return requestHandle;
    }
}
