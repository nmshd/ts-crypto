import { ISerializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, Encoding, IClearable } from "../CoreBuffer";
import { CryptoDerivation } from "../CryptoDerivation";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { DEFAULT_KEY_PAIR_SPEC } from "../crypto-layer/CryptoLayerUtils";
import { CryptoEncryptionWithCryptoLayer } from "../crypto-layer/encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoExchangeKeypairHandle } from "../crypto-layer/exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "../crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import { CryptoRelationshipSecretsHandle } from "../crypto-layer/relationship/CryptoRelationshipSecretsHandle";
import { CryptoSignatureKeypairHandle } from "../crypto-layer/signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKeyHandle } from "../crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import { CryptoPrivateStateReceiveHandle } from "../crypto-layer/state/CryptoPrivateStateReceiveHandle";
import { CryptoPrivateStateTransmitHandle } from "../crypto-layer/state/CryptoPrivateStateTransmitHandle";
import { CryptoPublicStateHandle } from "../crypto-layer/state/CryptoPublicStateHandle";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm, initCryptoEncryption } from "../encryption/CryptoEncryption";
import { CryptoEncryptionAlgorithmUtil } from "../encryption/CryptoEncryptionAlgorithmUtil";
import { CryptoSecretKey, ICryptoSecretKey } from "../encryption/CryptoSecretKey";
import { CryptoExchange, initCryptoExchange } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypair, ICryptoExchangeKeypair } from "../exchange/CryptoExchangeKeypair";
import { CryptoExchangePrivateKey } from "../exchange/CryptoExchangePrivateKey";
import { CryptoExchangePublicKey, ICryptoExchangePublicKey } from "../exchange/CryptoExchangePublicKey";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoHashAlgorithmUtil } from "../hash/CryptoHashAlgorithmUtil";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignatureKeypair, ICryptoSignatureKeypair } from "../signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKey, ICryptoSignaturePublicKey } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { ICryptoPrivateState } from "../state/CryptoPrivateState";
import { CryptoPrivateStateReceive } from "../state/CryptoPrivateStateReceive";
import { CryptoPrivateStateTransmit } from "../state/CryptoPrivateStateTransmit";
import { CryptoPublicState } from "../state/CryptoPublicState";
import { CryptoStateType } from "../state/CryptoStateType";
import { CryptoRelationshipPublicRequest } from "./CryptoRelationshipPublicRequest";
import { CryptoRelationshipPublicResponse } from "./CryptoRelationshipPublicResponse";
import { CryptoRelationshipRequestSecrets } from "./CryptoRelationshipRequestSecrets";
import { CryptoRelationshipType } from "./CryptoRelationshipType";

export interface ICryptoRelationshipSecrets extends ISerializable {
    id?: string;
    type: CryptoRelationshipType;
    exchangeKeypair: ICryptoExchangeKeypair | CryptoExchangeKeypairHandle;
    signatureKeypair: ICryptoSignatureKeypair | CryptoSignatureKeypairHandle;
    transmitState: ICryptoPrivateState | CryptoPrivateStateTransmitHandle;
    receiveState: ICryptoPrivateState | CryptoPrivateStateReceiveHandle;
    peerExchangeKey: ICryptoExchangePublicKey | CryptoExchangePublicKeyHandle;
    peerSignatureKey: ICryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;
    peerTemplateKey: ICryptoExchangePublicKey | CryptoExchangePublicKeyHandle;
    peerIdentityKey?: ICryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;
    requestSecretKey: ICryptoSecretKey | CryptoSecretKeyHandle;
}

@type("CryptoRelationshipSecrets")
export class CryptoRelationshipSecrets extends CryptoSerializable implements ICryptoRelationshipSecrets, IClearable {
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize({ alias: "typ" })
    public type: CryptoRelationshipType;

    @validate()
    @serialize({ alias: "exc" })
    public exchangeKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle;

    @validate()
    @serialize({ alias: "sig" })
    public signatureKeypair: CryptoSignatureKeypair | CryptoSignatureKeypairHandle;

    @validate()
    @serialize({ alias: "tx" })
    public transmitState: CryptoPrivateStateTransmit | CryptoPrivateStateTransmitHandle;

    @validate()
    @serialize({ alias: "rx" })
    public receiveState: CryptoPrivateStateReceive | CryptoPrivateStateReceiveHandle;

    @validate()
    @serialize({ alias: "pxk" })
    public peerExchangeKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle;

    @validate()
    @serialize({ alias: "psk" })
    public peerSignatureKey: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize({ alias: "ptk" })
    public peerTemplateKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle;

    @validate({ nullable: true })
    @serialize({ alias: "pik" })
    public peerIdentityKey?: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize({ alias: "rsk" })
    public requestSecretKey: CryptoSecretKey | CryptoSecretKeyHandle;

    /**
     * Determines if this relationship secrets is using the crypto-layer implementation
     * @returns True if using CAL, false if using libsodium
     */
    public isUsingCryptoLayer(): boolean {
        return (
            this.exchangeKeypair instanceof CryptoExchangeKeypairHandle &&
            this.signatureKeypair instanceof CryptoSignatureKeypairHandle &&
            this.transmitState instanceof CryptoPrivateStateTransmitHandle &&
            this.receiveState instanceof CryptoPrivateStateReceiveHandle &&
            this.peerExchangeKey instanceof CryptoExchangePublicKeyHandle &&
            this.peerSignatureKey instanceof CryptoSignaturePublicKeyHandle &&
            this.peerTemplateKey instanceof CryptoExchangePublicKeyHandle &&
            (this.peerIdentityKey === undefined || this.peerIdentityKey instanceof CryptoSignaturePublicKeyHandle) &&
            this.requestSecretKey instanceof CryptoSecretKeyHandle
        );
    }

    /**
     * Converts this relationship secrets to a CAL handle
     * @returns A promise resolving to a CAL secrets handle
     */
    public async toHandle(): Promise<CryptoRelationshipSecretsHandle> {
        if (this.isUsingCryptoLayer()) {
            return await CryptoRelationshipSecretsHandle.from({
                id: this.id,
                type: this.type,
                exchangeKeypair: this.exchangeKeypair as CryptoExchangeKeypairHandle,
                signatureKeypair: this.signatureKeypair as CryptoSignatureKeypairHandle,
                transmitState: this.transmitState as CryptoPrivateStateTransmitHandle,
                receiveState: this.receiveState as CryptoPrivateStateReceiveHandle,
                peerExchangeKey: this.peerExchangeKey as CryptoExchangePublicKeyHandle,
                peerSignatureKey: this.peerSignatureKey as CryptoSignaturePublicKeyHandle,
                peerTemplateKey: this.peerTemplateKey as CryptoExchangePublicKeyHandle,
                peerIdentityKey: this.peerIdentityKey as CryptoSignaturePublicKeyHandle | undefined,
                requestSecretKey: this.requestSecretKey as CryptoSecretKeyHandle
            });
        }

        throw new CryptoError(
            CryptoErrorCode.CalUninitializedKey,
            "Cannot create handle: this relationship secrets doesn't use crypto-layer handles"
        );
    }

    public clear(): void {
        if (this.exchangeKeypair instanceof CryptoExchangeKeypair) {
            this.exchangeKeypair.clear();
        }
        if (this.signatureKeypair instanceof CryptoSignatureKeypair) {
            this.signatureKeypair.clear();
        }
        if (this.transmitState instanceof CryptoPrivateStateTransmit) {
            this.transmitState.clear();
        }
        if (this.receiveState instanceof CryptoPrivateStateReceive) {
            this.receiveState.clear();
        }
        if (this.requestSecretKey instanceof CryptoSecretKey) {
            this.requestSecretKey.clear();
        }
    }

    public static from(value: ICryptoRelationshipSecrets): CryptoRelationshipSecrets {
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
        if (this.signatureKeypair instanceof CryptoSignatureKeypair) {
            return await CryptoSignatures.sign(content, this.signatureKeypair.privateKey, algorithm);
        }
        return await CryptoSignatures.sign(content, this.signatureKeypair.privateKey, algorithm);
    }

    /**
     * Verifies content with this relationship's signature keypair
     * @param content Content to verify
     * @param signature Signature to verify
     * @returns Promise resolving to true if verified, false otherwise
     */
    public async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        const publicKey =
            this.signatureKeypair instanceof CryptoSignatureKeypair
                ? this.signatureKeypair.publicKey
                : this.signatureKeypair.publicKey;
        return await CryptoSignatures.verify(content, signature, publicKey);
    }

    /**
     * Verifies content with the peer's signature key
     * @param content Content to verify
     * @param signature Signature to verify
     * @returns Promise resolving to true if verified, false otherwise
     */
    public async verifyPeer(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.peerSignatureKey);
    }

    /**
     * Verifies content with the peer's identity key
     * @param content Content to verify
     * @param signature Signature to verify
     * @returns Promise resolving to true if verified, false otherwise
     */
    public async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        if (!this.peerIdentityKey) {
            throw new CryptoError(
                CryptoErrorCode.RelationshipNoPeer,
                "The peer of this relationship is not set. You have to initialize this relationship with a peer first."
            );
        }
        return await CryptoSignatures.verify(content, signature, this.peerIdentityKey);
    }

    /**
     * Encrypts content using the transmit state
     * @param content Content to encrypt
     * @returns Promise resolving to an encrypted cipher
     */
    public async encrypt(content: CoreBuffer): Promise<CryptoCipher> {
        if (this.transmitState instanceof CryptoPrivateStateTransmitHandle) {
            // Use CAL implementation if we have a handle
            return await CryptoEncryptionWithCryptoLayer.encryptWithCounter(
                content,
                this.transmitState.secretKeyHandle,
                // this.transmitState.nonce,
                this.transmitState.counter
            );
        }
        // Use traditional implementation
        return await this.transmitState.encrypt(content);
    }

    /**
     * Decrypts own content using the transmit state
     * @param cipher Cipher to decrypt
     * @returns Promise resolving to decrypted plaintext
     */
    public async decryptOwn(cipher: CryptoCipher): Promise<CoreBuffer> {
        if (this.transmitState instanceof CryptoPrivateStateTransmitHandle) {
            // Use CAL implementation if we have a handle
            return await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                cipher,
                this.transmitState.secretKeyHandle,
                this.transmitState.nonce
                // cipher.counter !== undefined ? cipher.counter : this.transmitState.counter
            );
        }
        // Use traditional implementation
        return await this.transmitState.decrypt(cipher);
    }

    /**
     * Decrypts peer content using the receive state
     * @param cipher Cipher to decrypt
     * @param omitCounterCheck Whether to skip counter validation
     * @returns Promise resolving to decrypted plaintext
     */
    public async decryptPeer(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        if (this.receiveState instanceof CryptoPrivateStateReceiveHandle) {
            // Use CAL implementation if we have a handle
            if (omitCounterCheck) {
                return await CryptoEncryptionWithCryptoLayer.decrypt(
                    cipher,
                    this.receiveState.secretKeyHandle,
                    this.receiveState.nonce
                );
            }
            // Verify counter
            if (this.receiveState.counter !== cipher.counter && cipher.counter !== undefined) {
                throw new CryptoError(
                    CryptoErrorCode.StateWrongOrder,
                    `The current message seems to be out of order. The in order number would be ${this.receiveState.counter} and message is ${cipher.counter}.`
                );
            }

            const result = await CryptoEncryptionWithCryptoLayer.decryptWithCounter(
                cipher,
                this.receiveState.secretKeyHandle,
                this.receiveState.nonce
                // cipher.counter !== undefined ? cipher.counter : this.receiveState.counter
            );

            // Increment counter
            this.receiveState.counter++;

            return result;
        }
        // Use traditional implementation
        return await this.receiveState.decrypt(cipher, omitCounterCheck);
    }

    /**
     * Decrypts request content
     * @param cipher Cipher to decrypt
     * @returns Promise resolving to decrypted plaintext
     */
    public async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        if (this.requestSecretKey instanceof CryptoSecretKeyHandle) {
            return await CryptoEncryptionWithCryptoLayer.decrypt(cipher, this.requestSecretKey);
        }
        return await CryptoEncryption.decrypt(cipher, this.requestSecretKey);
    }

    /**
     * Creates a public response from these secrets
     * @returns A relationship public response
     */
    public toPublicResponse(): CryptoRelationshipPublicResponse {
        const publicKey =
            this.exchangeKeypair instanceof CryptoExchangeKeypair
                ? this.exchangeKeypair.publicKey
                : this.exchangeKeypair.publicKey;

        const signatureKey =
            this.signatureKeypair instanceof CryptoSignatureKeypair
                ? this.signatureKeypair.publicKey
                : this.signatureKeypair.publicKey;

        let state;
        if (this.transmitState instanceof CryptoPrivateStateTransmit) {
            state = this.transmitState.toPublicState();
        } else {
            state = new CryptoPublicStateHandle();
            state.algorithm = this.transmitState.algorithm;
            state.nonce = this.transmitState.nonce.clone();
            state.stateType = CryptoStateType.Transmit;
            state.id = this.transmitState.id;
        }

        return CryptoRelationshipPublicResponse.from({
            exchangeKey: publicKey,
            signatureKey: signatureKey,
            state: state
        });
    }

    /**
     * Creates relationship secrets from a response and request
     * @param response The relationship response
     * @param request The relationship request secrets
     * @param providerIdent Optional provider identifier for CAL
     * @returns Promise resolving to relationship secrets
     */
    public static async fromRelationshipResponse(
        response: CryptoRelationshipPublicResponse,
        request: CryptoRelationshipRequestSecrets,
        providerIdent?: ProviderIdentifier
    ): Promise<CryptoRelationshipSecrets> {
        // Initialize crypto modules with provider if provided
        if (providerIdent) {
            initCryptoEncryption(providerIdent);
            initCryptoExchange(providerIdent);
        }

        const signatureKeypair = request.signatureKeypair;
        const exchangeKeypair = request.exchangeKeypair;
        const requestSecretKey = request.secretKey;
        const peerExchangeKey = response.exchangeKey;
        const peerPublicTransmitState = response.state;
        const peerSignatureKey = response.signatureKey;
        const peerIdentityKey = request.peerIdentityKey;
        const peerTemplateKey = request.peerExchangeKey;

        // CAL implementation path
        if (
            providerIdent &&
            exchangeKeypair instanceof CryptoExchangeKeypairHandle &&
            peerExchangeKey instanceof CryptoExchangePublicKeyHandle
        ) {
            const derivedKey = await CryptoExchange.deriveRequestor(exchangeKeypair, peerExchangeKey);
            const ownType = CryptoRelationshipType.Requestor;

            const hashAlgorithm = CryptoHashAlgorithm.SHA512;
            // const defaultSpec = {
            //     ...DEFAULT_KEY_PAIR_SPEC,
            //     cipher: CryptoEncryptionAlgorithmUtil.toCalCipher(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305),
            //     signing_hash: CryptoHashAlgorithmUtil.toCalHash(hashAlgorithm)
            // };

            // Generate transmit state with CAL
            const transmitState = await CryptoPrivateStateTransmit.generate(
                undefined, // Generate new key
                undefined, // No ID
                CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                providerIdent,
                hashAlgorithm
            );

            // Create receive state appropriate for the key type
            let receiveState;
            if (requestSecretKey instanceof CryptoSecretKeyHandle) {
                receiveState = await CryptoPrivateStateReceive.fromNonce(
                    peerPublicTransmitState.nonce,
                    requestSecretKey
                );
            } else if (peerPublicTransmitState instanceof CryptoPublicStateHandle) {
                // Convert to CAL handle if possible
                receiveState = await CryptoPrivateStateReceive.fromPublicState(
                    peerPublicTransmitState,
                    derivedKey.receivingKey, // Use the derived key from CAL
                    0
                );
            } else {
                const stateHandle = await peerPublicTransmitState.toHandle();
                receiveState = await CryptoPrivateStateReceive.fromPublicState(stateHandle, derivedKey.receivingKey, 0);
            }

            return CryptoRelationshipSecrets.from({
                exchangeKeypair: exchangeKeypair,
                signatureKeypair: signatureKeypair,
                receiveState: receiveState,
                transmitState: transmitState,
                type: ownType,
                peerExchangeKey: peerExchangeKey,
                peerSignatureKey: peerSignatureKey,
                peerTemplateKey: peerTemplateKey,
                peerIdentityKey: peerIdentityKey,
                requestSecretKey: requestSecretKey
            });
        }

        // libsodium implementation path

        // Convert CAL handles to traditional objects if needed
        let resolvedExchangeKeypair = exchangeKeypair;
        if (exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            // Create a compatible keypair from the handle
            const pubKey = await CryptoExchangePublicKey.fromHandle(exchangeKeypair.publicKey);

            // We need to access the private key data - must be implemented in the crypto-layer
            const privateKeyStr = await exchangeKeypair.privateKey.toSerializedString();
            const privateKey = new CryptoExchangePrivateKey();
            privateKey.algorithm = pubKey.algorithm;
            privateKey.privateKey = CoreBuffer.fromString(privateKeyStr, Encoding.Base64_UrlSafe_NoPadding);

            resolvedExchangeKeypair = new CryptoExchangeKeypair();
            resolvedExchangeKeypair.publicKey = pubKey;
            resolvedExchangeKeypair.privateKey = privateKey;
        }

        const resolvedPeerExchangeKey =
            peerExchangeKey instanceof CryptoExchangePublicKeyHandle
                ? await CryptoExchangePublicKey.fromHandle(peerExchangeKey)
                : peerExchangeKey;

        const derivedKey = await CryptoExchange.deriveRequestor(
            resolvedExchangeKeypair as CryptoExchangeKeypair,
            resolvedPeerExchangeKey
        );

        const ownType = CryptoRelationshipType.Requestor;

        const [derivedTx, derivedRx] = await Promise.all([
            CryptoDerivation.deriveKeyFromBase(derivedKey.transmissionKey, 1, "RELREQ01"),
            CryptoDerivation.deriveKeyFromBase(derivedKey.receivingKey, 1, "RELTEM01")
        ]);

        // Create states using the traditional path
        const resolvedPeerPublicState =
            peerPublicTransmitState instanceof CryptoPublicStateHandle
                ? await CryptoPublicState.fromHandle(peerPublicTransmitState)
                : peerPublicTransmitState;

        const [receiveState, transmitState] = await Promise.all([
            CryptoPrivateStateReceive.fromPublicState(resolvedPeerPublicState, derivedRx.secretKey, 0),
            CryptoPrivateStateTransmit.from({
                algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                counter: 0,
                nonce: request.nonce,
                secretKey: derivedTx.secretKey,
                stateType: CryptoStateType.Transmit
            })
        ]);

        return CryptoRelationshipSecrets.from({
            exchangeKeypair: exchangeKeypair,
            signatureKeypair: signatureKeypair,
            receiveState: receiveState,
            transmitState: transmitState,
            type: ownType,
            peerExchangeKey: peerExchangeKey,
            peerSignatureKey: peerSignatureKey,
            peerTemplateKey: peerTemplateKey,
            peerIdentityKey: peerIdentityKey,
            requestSecretKey: requestSecretKey
        });
    }

    /**
     * Creates relationship secrets from a request
     * @param request The public request
     * @param templateExchangeKeypair The template exchange keypair
     * @param providerIdent Optional provider identifier for CAL
     * @returns Promise resolving to relationship secrets
     */
    public static async fromRelationshipRequest(
        request: CryptoRelationshipPublicRequest,
        templateExchangeKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        providerIdent?: ProviderIdentifier
    ): Promise<CryptoRelationshipSecrets> {
        return await this.fromPeerNonce(
            request.exchangeKey,
            request.ephemeralKey,
            request.signatureKey,
            request.nonce,
            templateExchangeKeypair,
            undefined,
            CryptoRelationshipType.Requestor,
            providerIdent
        );
    }

    /**
     * Creates relationship secrets from peer information
     * @param peerExchangeKey Peer's exchange key
     * @param peerTemplateKey Peer's template key
     * @param peerSignatureKey Peer's signature key
     * @param peerGeneratedNonce Peer's nonce
     * @param templateExchangeKeypair Template exchange keypair
     * @param peerIdentityKey Optional peer identity key
     * @param peerType Peer's relationship type
     * @param providerIdent Optional provider identifier for CAL
     * @returns Promise resolving to relationship secrets
     */
    public static async fromPeerNonce(
        peerExchangeKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        peerTemplateKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        peerSignatureKey: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle,
        peerGeneratedNonce: CoreBuffer,
        templateExchangeKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        peerIdentityKey?: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle,
        peerType: CryptoRelationshipType = CryptoRelationshipType.Requestor,
        providerIdent?: ProviderIdentifier
    ): Promise<CryptoRelationshipSecrets> {
        // Initialize crypto modules with provider if provided
        if (providerIdent) {
            initCryptoEncryption(providerIdent);
            initCryptoExchange(providerIdent);
        }

        // CAL implementation path
        if (
            providerIdent &&
            peerExchangeKey instanceof CryptoExchangePublicKeyHandle &&
            peerTemplateKey instanceof CryptoExchangePublicKeyHandle &&
            templateExchangeKeypair instanceof CryptoExchangeKeypairHandle
        ) {
            const hashAlgorithm = CryptoHashAlgorithm.SHA512;
            const defaultSpec = {
                ...DEFAULT_KEY_PAIR_SPEC,
                signing_hash: CryptoHashAlgorithmUtil.toCalHash(hashAlgorithm)
            };

            // Generate keypairs for the relationship
            const [signatureKeypair, exchangeKeypair] = await Promise.all([
                CryptoSignatures.generateKeypairHandle(providerIdent, defaultSpec),
                CryptoExchange.generateKeypairHandle(providerIdent, defaultSpec)
            ]);

            // Derive keys based on relationship type
            let derivedKey;
            let ownType;
            switch (peerType) {
                case CryptoRelationshipType.Requestor:
                    derivedKey = await CryptoExchange.deriveTemplator(exchangeKeypair, peerExchangeKey);
                    ownType = CryptoRelationshipType.Templator;
                    break;
                case CryptoRelationshipType.Templator:
                    derivedKey = await CryptoExchange.deriveRequestor(exchangeKeypair, peerExchangeKey);
                    ownType = CryptoRelationshipType.Requestor;
                    break;
                default:
                    throw new CryptoError(CryptoErrorCode.RelationshipNoRequestorNorTemplator);
            }

            // Create receive state with the appropriate key
            const receiveState = await CryptoPrivateStateReceive.fromNonce(peerGeneratedNonce, derivedKey.receivingKey);

            // Generate transmit state
            const transmitState = await CryptoPrivateStateTransmit.generate(
                undefined, // Generate new key
                undefined, // No ID
                CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                providerIdent,
                hashAlgorithm
            );

            // Create master key for the relationship
            const masterKey = await CryptoExchange.deriveTemplator(templateExchangeKeypair, peerTemplateKey);

            // Generate secret key with the appropriate specs
            const secretKeySpec = {
                cipher: CryptoEncryptionAlgorithmUtil.toCalCipher(masterKey.algorithm),
                signing_hash: defaultSpec.signing_hash,
                ephemeral: false,
                non_exportable: false
            };

            const secretKey = await CryptoEncryption.generateKeyHandle(providerIdent, secretKeySpec);

            return CryptoRelationshipSecrets.from({
                exchangeKeypair: exchangeKeypair,
                signatureKeypair: signatureKeypair,
                receiveState: receiveState,
                transmitState: transmitState,
                type: ownType,
                peerExchangeKey: peerExchangeKey,
                peerSignatureKey: peerSignatureKey,
                peerTemplateKey: peerTemplateKey,
                peerIdentityKey: peerIdentityKey,
                requestSecretKey: secretKey
            });
        }

        // libsodium implementation path
        const [signatureKeypair, exchangeKeypair] = await Promise.all([
            CryptoSignatures.generateKeypair(),
            CryptoExchange.generateKeypair()
        ]);

        // Handle mixed types by converting handles to traditional objects if needed
        const resolvedPeerExchangeKey =
            peerExchangeKey instanceof CryptoExchangePublicKeyHandle
                ? await CryptoExchangePublicKey.fromHandle(peerExchangeKey)
                : peerExchangeKey;

        // Convert template keypair if needed
        let resolvedTemplateKeypair = templateExchangeKeypair;
        if (templateExchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            // Create a compatible keypair from the handle
            const pubKey = await CryptoExchangePublicKey.fromHandle(templateExchangeKeypair.publicKey);

            // We need to access the private key data
            const privateKeyStr = await templateExchangeKeypair.privateKey.toSerializedString();
            const privateKey = new CryptoExchangePrivateKey();
            privateKey.algorithm = pubKey.algorithm;
            privateKey.privateKey = CoreBuffer.fromString(privateKeyStr, Encoding.Base64_UrlSafe_NoPadding);

            resolvedTemplateKeypair = new CryptoExchangeKeypair();
            resolvedTemplateKeypair.publicKey = pubKey;
            resolvedTemplateKeypair.privateKey = privateKey;
        }

        const resolvedPeerTemplateKey =
            peerTemplateKey instanceof CryptoExchangePublicKeyHandle
                ? await CryptoExchangePublicKey.fromHandle(peerTemplateKey)
                : peerTemplateKey;

        // Derive keys based on relationship type
        let derivedKey;
        let ownType;
        switch (peerType) {
            case CryptoRelationshipType.Requestor:
                derivedKey = await CryptoExchange.deriveTemplator(exchangeKeypair, resolvedPeerExchangeKey);
                ownType = CryptoRelationshipType.Templator;
                break;
            case CryptoRelationshipType.Templator:
                derivedKey = await CryptoExchange.deriveRequestor(exchangeKeypair, resolvedPeerExchangeKey);
                ownType = CryptoRelationshipType.Requestor;
                break;
            default:
                throw new CryptoError(CryptoErrorCode.RelationshipNoRequestorNorTemplator);
        }

        // Derive keys for states
        const [derivedTx, derivedRx] = await Promise.all([
            CryptoDerivation.deriveKeyFromBase(derivedKey.transmissionKey, 1, "RELTEM01"),
            CryptoDerivation.deriveKeyFromBase(derivedKey.receivingKey, 1, "RELREQ01")
        ]);

        // Create states
        const [receiveState, transmitState] = await Promise.all([
            CryptoPrivateStateReceive.fromNonce(peerGeneratedNonce, derivedRx.secretKey),
            CryptoPrivateStateTransmit.generate(derivedTx.secretKey)
        ]);

        // Create master key and derive request secret
        const masterKey = await CryptoExchange.deriveTemplator(
            resolvedTemplateKeypair as CryptoExchangeKeypair,
            resolvedPeerTemplateKey
        );

        const secretKey = await CryptoDerivation.deriveKeyFromBase(masterKey.receivingKey, 1, "REQTMP01");

        return CryptoRelationshipSecrets.from({
            exchangeKeypair: exchangeKeypair,
            signatureKeypair: signatureKeypair,
            receiveState: receiveState,
            transmitState: transmitState,
            type: ownType,
            peerExchangeKey: peerExchangeKey,
            peerSignatureKey: peerSignatureKey,
            peerTemplateKey: peerTemplateKey,
            peerIdentityKey: peerIdentityKey,
            requestSecretKey: secretKey
        });
    }

    /**
     * Creates relationship secrets from a CAL handle
     * @param handle The CAL handle to convert from
     * @returns Promise resolving to relationship secrets
     */
    public static async fromHandle(handle: CryptoRelationshipSecretsHandle): Promise<CryptoRelationshipSecrets> {
        return CryptoRelationshipSecrets.from({
            id: handle.id,
            type: handle.type,
            exchangeKeypair: handle.exchangeKeypair,
            signatureKeypair: handle.signatureKeypair,
            transmitState: handle.transmitState,
            receiveState: handle.receiveState,
            peerExchangeKey: handle.peerExchangeKey,
            peerSignatureKey: handle.peerSignatureKey,
            peerTemplateKey: handle.peerTemplateKey,
            peerIdentityKey: handle.peerIdentityKey,
            requestSecretKey: handle.requestSecretKey
        });
    }
}
