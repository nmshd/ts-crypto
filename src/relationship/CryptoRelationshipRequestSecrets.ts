import { ISerializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CryptoRelationshipRequestSecretsHandle } from "src/crypto-layer/relationship/CryptoRelationshipPublicRequestHandle";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { DEFAULT_KEY_PAIR_SPEC } from "../crypto-layer/CryptoLayerUtils";
import { CryptoEncryptionWithCryptoLayer } from "../crypto-layer/encryption/CryptoEncryptionWithCryptoLayer";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoExchangeKeypairHandle } from "../crypto-layer/exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "../crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import { CryptoSignatureKeypairHandle } from "../crypto-layer/signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKeyHandle } from "../crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import { CryptoDerivation } from "../CryptoDerivation";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, initCryptoEncryption } from "../encryption/CryptoEncryption";
import { CryptoEncryptionAlgorithmUtil } from "../encryption/CryptoEncryptionAlgorithmUtil";
import { CryptoSecretKey, ICryptoSecretKey } from "../encryption/CryptoSecretKey";
import { CryptoExchange, initCryptoExchange } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypair, ICryptoExchangeKeypair } from "../exchange/CryptoExchangeKeypair";
import { CryptoExchangePublicKey, ICryptoExchangePublicKey } from "../exchange/CryptoExchangePublicKey";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoHashAlgorithmUtil } from "../hash/CryptoHashAlgorithmUtil";
import { CryptoRandom } from "../random/CryptoRandom";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignatureKeypair, ICryptoSignatureKeypair } from "../signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKey, ICryptoSignaturePublicKey } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { CryptoRelationshipPublicRequest } from "./CryptoRelationshipPublicRequest";

export interface ICryptoRelationshipRequestSecrets extends ISerializable {
    id?: string;
    exchangeKeypair: ICryptoExchangeKeypair | CryptoExchangeKeypairHandle;
    signatureKeypair: ICryptoSignatureKeypair | CryptoSignatureKeypairHandle;
    ephemeralKeypair: ICryptoExchangeKeypair | CryptoExchangeKeypairHandle;
    peerIdentityKey: ICryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;
    peerExchangeKey: ICryptoExchangePublicKey | CryptoExchangePublicKeyHandle;
    secretKey: ICryptoSecretKey | CryptoSecretKeyHandle;
    nonce: ICoreBuffer;
}

@type("CryptoRelationshipRequestSecrets")
export class CryptoRelationshipRequestSecrets
    extends CryptoSerializable
    implements ICryptoRelationshipRequestSecrets, IClearable
{
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize({ alias: "exc" })
    public exchangeKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle;

    @validate()
    @serialize({ alias: "eph" })
    public ephemeralKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle;

    @validate()
    @serialize({ alias: "sig" })
    public signatureKeypair: CryptoSignatureKeypair | CryptoSignatureKeypairHandle;

    @validate()
    @serialize({ alias: "pik" })
    public peerIdentityKey: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize({ alias: "pxk" })
    public peerExchangeKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle;

    @validate()
    @serialize({ alias: "key" })
    public secretKey: CryptoSecretKey | CryptoSecretKeyHandle;

    @validate()
    @serialize({ alias: "nnc" })
    public nonce: CoreBuffer;

    /**
     * Determines if this request secrets is using the crypto-layer implementation
     * @returns True if using CAL, false if using libsodium
     */
    public isUsingCryptoLayer(): boolean {
        return (
            this.exchangeKeypair instanceof CryptoExchangeKeypairHandle &&
            this.ephemeralKeypair instanceof CryptoExchangeKeypairHandle &&
            this.signatureKeypair instanceof CryptoSignatureKeypairHandle &&
            this.secretKey instanceof CryptoSecretKeyHandle &&
            this.peerIdentityKey instanceof CryptoSignaturePublicKeyHandle &&
            this.peerExchangeKey instanceof CryptoExchangePublicKeyHandle
        );
    }

    public clear(): void {
        if (this.exchangeKeypair instanceof CryptoExchangeKeypair) {
            this.exchangeKeypair.clear();
        }
        if (this.ephemeralKeypair instanceof CryptoExchangeKeypair) {
            this.ephemeralKeypair.clear();
        }
        if (this.signatureKeypair instanceof CryptoSignatureKeypair) {
            this.signatureKeypair.clear();
        }
        if (this.secretKey instanceof CryptoSecretKey) {
            this.secretKey.clear();
        }
        this.nonce.clear();
    }

    /**
     * Converts this request secrets to a CAL handle
     * @returns A promise resolving to a CAL request secrets handle
     */
    public async toHandle(): Promise<CryptoRelationshipRequestSecretsHandle> {
        if (this.isUsingCryptoLayer()) {
            return await CryptoRelationshipRequestSecretsHandle.from({
                id: this.id,
                exchangeKeypair: this.exchangeKeypair as CryptoExchangeKeypairHandle,
                ephemeralKeypair: this.ephemeralKeypair as CryptoExchangeKeypairHandle,
                signatureKeypair: this.signatureKeypair as CryptoSignatureKeypairHandle,
                peerIdentityKey: this.peerIdentityKey as CryptoSignaturePublicKeyHandle,
                peerExchangeKey: this.peerExchangeKey as CryptoExchangePublicKeyHandle,
                secretKey: this.secretKey as CryptoSecretKeyHandle,
                nonce: this.nonce
            });
        }

        throw new CryptoError(
            CryptoErrorCode.CalUninitializedKey,
            "Cannot create handle: this request secrets doesn't use crypto-layer handles"
        );
    }

    public static from(value: ICryptoRelationshipRequestSecrets): CryptoRelationshipRequestSecrets {
        return this.fromAny(value);
    }

    /**
     * Signs content using the signature keypair
     * @param content Content to sign
     * @param algorithm Hash algorithm to use
     * @returns Promise resolving to a signature
     */
    public async sign(
        content: CoreBuffer,
        algorithm: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA256
    ): Promise<CryptoSignature> {
        return await CryptoSignatures.sign(
            content,
            this.signatureKeypair instanceof CryptoSignatureKeypair
                ? this.signatureKeypair.privateKey
                : this.signatureKeypair.privateKey,
            algorithm
        );
    }

    /**
     * Verifies content with this request's signature keypair
     * @param content Content to verify
     * @param signature Signature to verify
     * @returns Promise resolving to true if verified, false otherwise
     */
    public async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(
            content,
            signature,
            this.signatureKeypair instanceof CryptoSignatureKeypair
                ? this.signatureKeypair.publicKey
                : this.signatureKeypair.publicKey
        );
    }

    /**
     * Verifies content with the peer's identity key
     * @param content Content to verify
     * @param signature Signature to verify
     * @returns Promise resolving to true if verified, false otherwise
     */
    public async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.peerIdentityKey);
    }

    /**
     * Encrypts request content
     * @param content Content to encrypt
     * @returns Promise resolving to an encrypted cipher
     */
    public async encryptRequest(content: CoreBuffer): Promise<CryptoCipher> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoEncryptionWithCryptoLayer.encrypt(content, this.secretKey);
        } else {
            return await CryptoEncryption.encrypt(content, this.secretKey as CryptoSecretKey);
        }
    }

    /**
     * Decrypts request content
     * @param cipher Cipher to decrypt
     * @returns Promise resolving to decrypted plaintext
     */
    public async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoEncryptionWithCryptoLayer.decrypt(cipher, this.secretKey);
        } else {
            return await CryptoEncryption.decrypt(cipher, this.secretKey as CryptoSecretKey);
        }
    }

    /**
     * Creates a public request from these secrets
     * @returns A relationship public request
     */
    public toPublicRequest(): CryptoRelationshipPublicRequest {
        return CryptoRelationshipPublicRequest.from({
            id: this.id,
            exchangeKey:
                this.exchangeKeypair instanceof CryptoExchangeKeypair
                    ? this.exchangeKeypair.publicKey
                    : this.exchangeKeypair.publicKey,
            signatureKey:
                this.signatureKeypair instanceof CryptoSignatureKeypair
                    ? this.signatureKeypair.publicKey
                    : this.signatureKeypair.publicKey,
            ephemeralKey:
                this.ephemeralKeypair instanceof CryptoExchangeKeypair
                    ? this.ephemeralKeypair.publicKey
                    : this.ephemeralKeypair.publicKey,
            nonce: this.nonce
        });
    }

    /**
     * Creates request secrets from a peer's keys
     * @param peerExchangeKey Peer's exchange key
     * @param peerIdentityKey Peer's identity key
     * @param providerIdent Optional provider identifier for CAL
     * @returns Promise resolving to relationship request secrets
     */
    public static async fromPeer(
        peerExchangeKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        peerIdentityKey: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle,
        providerIdent?: ProviderIdentifier
    ): Promise<CryptoRelationshipRequestSecrets> {
        // Initialize encryption and exchange modules with provider if provided
        if (providerIdent) {
            initCryptoEncryption(providerIdent);
            initCryptoExchange(providerIdent);
        }

        // CAL implementation path
        if (
            providerIdent &&
            peerExchangeKey instanceof CryptoExchangePublicKeyHandle &&
            peerIdentityKey instanceof CryptoSignaturePublicKeyHandle
        ) {
            const hashAlgorithm = CryptoHashAlgorithm.SHA512;
            const defaultSpec = {
                ...DEFAULT_KEY_PAIR_SPEC,
                signing_hash: CryptoHashAlgorithmUtil.toCalHash(hashAlgorithm)
            };

            // Generate all required keypairs and nonce
            const [exchangeKeypair, ephemeralKeypair, signatureKeypair, nonce] = await Promise.all([
                CryptoExchange.generateKeypairHandle(providerIdent, defaultSpec),
                CryptoExchange.generateKeypairHandle(providerIdent, defaultSpec),
                CryptoSignatures.generateKeypairHandle(providerIdent, defaultSpec),
                CryptoRandom.bytes(24)
            ]);

            // Derive the master key
            const masterKey = await CryptoExchange.deriveRequestor(ephemeralKeypair, peerExchangeKey);

            // Create the secret key for encryption
            const secretKeySpec = {
                cipher: CryptoEncryptionAlgorithmUtil.toCalCipher(masterKey.algorithm),
                signing_hash: defaultSpec.signing_hash,
                ephemeral: false,
                non_exportable: false
            };

            const secretKey = await CryptoEncryption.generateKey(masterKey.algorithm, providerIdent, secretKeySpec);

            return CryptoRelationshipRequestSecrets.from({
                exchangeKeypair: exchangeKeypair,
                ephemeralKeypair: ephemeralKeypair,
                signatureKeypair: signatureKeypair,
                peerExchangeKey: peerExchangeKey,
                peerIdentityKey: peerIdentityKey,
                secretKey: secretKey,
                nonce: nonce
            });
        }

        // libsodium implementation path
        else {
            const [exchangeKeypair, ephemeralKeypair, signatureKeypair, nonce] = await Promise.all([
                CryptoExchange.generateKeypair(),
                CryptoExchange.generateKeypair(),
                CryptoSignatures.generateKeypair(),
                CryptoRandom.bytes(24)
            ]);

            // Handle mixed types for peer keys
            const resolvedPeerExchangeKey =
                peerExchangeKey instanceof CryptoExchangePublicKeyHandle
                    ? await CryptoExchangePublicKey.fromHandle(peerExchangeKey)
                    : peerExchangeKey;

            const masterKey = await CryptoExchange.deriveRequestor(
                ephemeralKeypair as CryptoExchangeKeypair,
                resolvedPeerExchangeKey as CryptoExchangePublicKey
            );

            const secretKey = await CryptoDerivation.deriveKeyFromBase(masterKey.transmissionKey, 1, "REQTMP01");

            return CryptoRelationshipRequestSecrets.from({
                exchangeKeypair: exchangeKeypair,
                ephemeralKeypair: ephemeralKeypair,
                signatureKeypair: signatureKeypair,
                peerExchangeKey: peerExchangeKey,
                peerIdentityKey: peerIdentityKey,
                secretKey: secretKey,
                nonce: nonce
            });
        }
    }

    /**
     * Creates request secrets from a CAL handle
     * @param handle The CAL handle to convert from
     * @returns Promise resolving to request secrets
     */
    public static async fromHandle(
        handle: CryptoRelationshipRequestSecretsHandle
    ): Promise<CryptoRelationshipRequestSecrets> {
        return CryptoRelationshipRequestSecrets.from({
            id: handle.id,
            exchangeKeypair: handle.exchangeKeypair,
            ephemeralKeypair: handle.ephemeralKeypair,
            signatureKeypair: handle.signatureKeypair,
            peerIdentityKey: handle.peerIdentityKey,
            peerExchangeKey: handle.peerExchangeKey,
            secretKey: handle.secretKey,
            nonce: handle.nonce
        });
    }
}
