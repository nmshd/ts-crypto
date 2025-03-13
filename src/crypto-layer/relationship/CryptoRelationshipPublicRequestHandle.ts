import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoRandom } from "../../random/CryptoRandom";
import { CryptoSignature } from "../../signature/CryptoSignature";
import { CryptoEncryptionWithCryptoLayer } from "../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
import { CryptoExchangeWithCryptoLayer } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "../exchange/CryptoExchangePublicKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "../signature/CryptoSignaturePublicKeyHandle";
import { CryptoSignaturesWithCryptoLayer } from "../signature/CryptoSignatures";

/**
 * Serialized form of CryptoRelationshipPublicRequestHandle.
 */
export interface ICryptoRelationshipPublicRequestHandleSerialized extends ISerialized {
    id?: string;
    exc: any;
    sig: any;
    eph: any;
    nnc: string;
}

/**
 * Interface defining the structure of CryptoRelationshipPublicRequestHandle.
 */
export interface ICryptoRelationshipPublicRequestHandle extends ISerializable {
    id?: string;
    exchangeKey: CryptoExchangePublicKeyHandle;
    signatureKey: CryptoSignaturePublicKeyHandle;
    ephemeralKey: CryptoExchangePublicKeyHandle;
    nonce: CoreBuffer;
}

/**
 * Represents a public request handle for establishing cryptographic relationships.
 *
 * This class encapsulates the public keys and cryptographic material needed for
 * secure communication establishment between parties. It contains exchange keys,
 * signature keys, ephemeral keys for forward secrecy, and a nonce for preventing
 * replay attacks.
 */
@type("CryptoRelationshipPublicRequestHandle")
export class CryptoRelationshipPublicRequestHandle
    extends CryptoSerializableAsync
    implements ICryptoRelationshipPublicRequestHandle, IClearable
{
    /**
     * Optional identifier for the request handle.
     */
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    /**
     * The public key used for key exchange operations.
     */
    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKeyHandle;

    /**
     * The public key used for signature verification.
     */
    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKeyHandle;

    /**
     * An ephemeral public key used for providing forward secrecy.
     */
    @validate()
    @serialize()
    public ephemeralKey: CryptoExchangePublicKeyHandle;

    /**
     * A cryptographic nonce (number used once) to prevent replay attacks.
     */
    @validate()
    @serialize()
    public nonce: CoreBuffer;

    /**
     * Converts the handle to a JSON representation.
     *
     * @param verbose - If true, includes the type information in the output.
     * @returns A serialized representation of the handle.
     */
    public override toJSON(verbose = true): ICryptoRelationshipPublicRequestHandleSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            eph: this.ephemeralKey.toJSON(false),
            nnc: this.nonce.toBase64URL(),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicRequestHandle" : undefined
        };
    }

    /**
     * Clears sensitive data from memory.
     * Implements the IClearable interface to securely remove cryptographic material.
     */
    public clear(): void {
        this.nonce.clear();
    }

    /**
     * Creates a new relationship request handle using peer's public keys.
     *
     * This method generates an ephemeral keypair and a random nonce to establish
     * a secure relationship with the peer.
     *
     * @param providerName - The name of the cryptographic provider to use.
     * @param peerExchangeKey - The peer's public key for key exchange.
     * @param peerSignatureKey - The peer's public key for signature verification.
     * @returns A Promise resolving to a new CryptoRelationshipPublicRequestHandle.
     */
    public static async fromPeer(
        providerName: string,
        peerExchangeKey: CryptoExchangePublicKeyHandle,
        peerSignatureKey: CryptoSignaturePublicKeyHandle
    ): Promise<CryptoRelationshipPublicRequestHandle> {
        const ephemeralKeypair: CryptoExchangeKeypairHandle = await CryptoExchangeWithCryptoLayer.generateKeypair(
            { providerName },
            peerExchangeKey.spec
        );

        const nonce = await CryptoRandom.bytes(24);

        const handle = new CryptoRelationshipPublicRequestHandle();
        handle.exchangeKey = peerExchangeKey;
        handle.signatureKey = peerSignatureKey;
        handle.ephemeralKey = ephemeralKeypair.publicKey;
        handle.nonce = nonce;

        return handle;
    }

    /**
     * Creates a CryptoRelationshipPublicRequestHandle from an existing handle or interface.
     *
     * @param value - The source handle or interface to create from.
     * @returns A Promise resolving to a new CryptoRelationshipPublicRequestHandle.
     */
    public static async from(
        value: CryptoRelationshipPublicRequestHandle | ICryptoRelationshipPublicRequestHandle
    ): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.fromAny(value);
    }

    /**
     * Pre-processes input data before deserialization.
     * Converts compact JSON format to the full property names.
     *
     * @param value - The value to pre-process.
     * @returns The pre-processed value.
     */
    protected static override preFrom(value: any): any {
        if (value.exc) {
            value = {
                exchangeKey: value.exc,
                signatureKey: value.sig,
                ephemeralKey: value.eph,
                nonce: value.nnc,
                id: value.id
            };
        }
        return value;
    }

    /**
     * Creates a CryptoRelationshipPublicRequestHandle from a serialized JSON object.
     *
     * @param value - The serialized JSON object.
     * @returns A Promise resolving to a new CryptoRelationshipPublicRequestHandle.
     */
    public static async fromJSON(
        value: ICryptoRelationshipPublicRequestHandleSerialized
    ): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.fromAny(value);
    }

    /**
     * Creates a CryptoRelationshipPublicRequestHandle from a Base64-encoded string.
     *
     * @param value - The Base64-encoded string.
     * @returns A Promise resolving to a new CryptoRelationshipPublicRequestHandle.
     */
    public static async fromBase64(value: string): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Verifies a signature against content using the handle's signature key.
     *
     * @param content - The content that was signed.
     * @param signature - The signature to verify.
     * @returns A Promise resolving to a boolean indicating whether the signature is valid.
     */
    public async verify(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.signatureKey);
    }

    /**
     * Encrypts request content using the provided secret key.
     *
     * @param content - The content to encrypt.
     * @param secretKey - The secret key to use for encryption.
     * @returns A Promise resolving to a CryptoCipher containing the encrypted content.
     */
    public async encryptRequest(content: CoreBuffer, secretKey: CryptoSecretKeyHandle): Promise<CryptoCipher> {
        return await CryptoEncryptionWithCryptoLayer.encrypt(content, secretKey);
    }

    /**
     * Decrypts request content using the provided secret key and the handle's nonce.
     *
     * @param cipher - The encrypted content.
     * @param secretKey - The secret key to use for decryption.
     * @returns A Promise resolving to a CoreBuffer containing the decrypted content.
     */
    public async decryptRequest(cipher: CryptoCipher, secretKey: CryptoSecretKeyHandle): Promise<CoreBuffer> {
        return await CryptoEncryptionWithCryptoLayer.decrypt(cipher, secretKey, this.nonce);
    }
}
