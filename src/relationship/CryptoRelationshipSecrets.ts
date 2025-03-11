import { serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoDerivation } from "../CryptoDerivation";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoSecretKey } from "../encryption/CryptoSecretKey";
import { CryptoExchange } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypair } from "../exchange/CryptoExchangeKeypair";
import { CryptoExchangePublicKey } from "../exchange/CryptoExchangePublicKey";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignatureKeypair } from "../signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKey } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { ICryptoPrivateState } from "../state/CryptoPrivateState";
import { CryptoPrivateStateReceive } from "../state/CryptoPrivateStateReceive";
import { CryptoPrivateStateTransmit } from "../state/CryptoPrivateStateTransmit";
import { CryptoStateType } from "../state/CryptoStateType";
import { CryptoRelationshipPublicRequest } from "./CryptoRelationshipPublicRequest";
import { CryptoRelationshipPublicResponse } from "./CryptoRelationshipPublicResponse";
import { CryptoRelationshipRequestSecrets } from "./CryptoRelationshipRequestSecrets";
import { CryptoRelationshipType } from "./CryptoRelationshipType";

// The handle-based imports for the unified approach
import { CryptoExchangeKeypairHandle } from "src/crypto-layer/exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "src/crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import { CryptoRelationshipPublicRequestHandle } from "src/crypto-layer/relationship/CryptoRelationshipPublicRequestHandle";
import { CryptoRelationshipRequestSecretsHandle } from "src/crypto-layer/relationship/CryptoRelationshipRequestSecretsHandle";
import { CryptoSignaturePublicKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import { CryptoRelationshipPublicResponseHandle } from "../crypto-layer/relationship/CryptoRelationshipPublicResponseHandle";
import { CryptoRelationshipSecretsHandle } from "../crypto-layer/relationship/CryptoRelationshipSecretsHandle";

/**
 * The original interface describing libsodium-based relationship secrets.
 */
export interface ICryptoRelationshipSecrets {
    id?: string;
    type: CryptoRelationshipType;
    exchangeKeypair: CryptoExchangeKeypair;
    signatureKeypair: CryptoSignatureKeypair;
    transmitState: ICryptoPrivateState;
    receiveState: ICryptoPrivateState;
    peerExchangeKey: CryptoExchangePublicKey;
    peerSignatureKey: CryptoSignaturePublicKey;
    peerTemplateKey: CryptoExchangePublicKey;
    peerIdentityKey?: CryptoSignaturePublicKey;
    requestSecretKey: CryptoSecretKey;
}

/**
 * The libsodium-based relationship secrets class.
 */
@type("CryptoRelationshipSecretsWithLibsodium")
export class CryptoRelationshipSecretsWithLibsodium extends CryptoSerializable implements ICryptoRelationshipSecrets {
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize({ alias: "typ" })
    public type: CryptoRelationshipType;

    @validate()
    @serialize({ alias: "exc" })
    public exchangeKeypair: CryptoExchangeKeypair;

    @validate()
    @serialize({ alias: "sig" })
    public signatureKeypair: CryptoSignatureKeypair;

    @validate()
    @serialize({ alias: "tx" })
    public transmitState: CryptoPrivateStateTransmit;

    @validate()
    @serialize({ alias: "rx" })
    public receiveState: CryptoPrivateStateReceive;

    @validate()
    @serialize({ alias: "pxk" })
    public peerExchangeKey: CryptoExchangePublicKey;

    @validate()
    @serialize({ alias: "psk" })
    public peerSignatureKey: CryptoSignaturePublicKey;

    @validate()
    @serialize({ alias: "ptk" })
    public peerTemplateKey: CryptoExchangePublicKey;

    @validate({ nullable: true })
    @serialize({ alias: "pik" })
    public peerIdentityKey?: CryptoSignaturePublicKey;

    @validate()
    @serialize({ alias: "rsk" })
    public requestSecretKey: CryptoSecretKey;

    public static from(value: ICryptoRelationshipSecrets): CryptoRelationshipSecretsWithLibsodium {
        return this.fromAny(value);
    }

    public async sign(
        content: CoreBuffer,
        algorithm: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA256
    ): Promise<CryptoSignature> {
        return await CryptoSignatures.sign(content, this.signatureKeypair.privateKey, algorithm);
    }

    public async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.signatureKeypair.publicKey);
    }

    public async verifyPeer(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.peerSignatureKey);
    }

    public async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        if (!this.peerIdentityKey) {
            throw new CryptoError(
                CryptoErrorCode.RelationshipNoPeer,
                "The peer identity key is not set. This relationship must be initialized with a peer's identity key."
            );
        }
        return await CryptoSignatures.verify(content, signature, this.peerIdentityKey);
    }

    public async encrypt(content: CoreBuffer): Promise<CryptoCipher> {
        return await this.transmitState.encrypt(content);
    }

    public async decryptOwn(cipher: CryptoCipher): Promise<CoreBuffer> {
        return await this.transmitState.decrypt(cipher);
    }

    public async decryptPeer(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        return await this.receiveState.decrypt(cipher, omitCounterCheck);
    }

    public async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        return await CryptoEncryption.decrypt(cipher, this.requestSecretKey);
    }

    public toPublicResponse(): CryptoRelationshipPublicResponse {
        const publicResponse = new CryptoRelationshipPublicResponse();
        publicResponse.exchangeKey = this.exchangeKeypair.publicKey;
        publicResponse.signatureKey = this.signatureKeypair.publicKey;
        publicResponse.state = this.transmitState.toPublicState();
        return publicResponse;
    }

    /**
     * Creates a libsodium-based relationship secrets from a relationship public response,
     * typically used by the requestor after receiving the templator's response.
     */
    public static async fromRelationshipResponse(
        response: CryptoRelationshipPublicResponse,
        request: CryptoRelationshipRequestSecrets
    ): Promise<CryptoRelationshipSecretsWithLibsodium> {
        const signatureKeypair = request.signatureKeypair;
        const exchangeKeypair = request.exchangeKeypair;
        const requestSecretKey = request.secretKey;
        const peerExchangeKey = response.exchangeKey;
        const peerPublicTransmitState = response.state;
        const peerSignatureKey = response.signatureKey;
        const peerIdentityKey = request.peerIdentityKey;
        const peerTemplateKey = request.peerExchangeKey;

        const derivedKey = await CryptoExchange.deriveRequestor(exchangeKeypair, peerExchangeKey);
        const ownType = CryptoRelationshipType.Requestor;

        const [derivedTx, derivedRx] = await Promise.all([
            CryptoDerivation.deriveKeyFromBase(derivedKey.transmissionKey, 1, "RELREQ01"),
            CryptoDerivation.deriveKeyFromBase(derivedKey.receivingKey, 1, "RELTEM01")
        ]);

        const [receiveState, transmitState] = await Promise.all([
            CryptoPrivateStateReceive.fromPublicState(peerPublicTransmitState, derivedRx.secretKey, 0),
            CryptoPrivateStateTransmit.from({
                algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                counter: 0,
                nonce: request.nonce,
                secretKey: derivedTx.secretKey,
                stateType: CryptoStateType.Transmit
            })
        ]);

        return this.from({
            exchangeKeypair,
            signatureKeypair,
            receiveState,
            transmitState,
            type: ownType,
            peerExchangeKey,
            peerSignatureKey,
            peerTemplateKey,
            peerIdentityKey,
            requestSecretKey
        });
    }

    /**
     * Creates a libsodium-based relationship secrets from a relationship public request,
     * typically used by the templator after receiving the requestor's data.
     */
    public static async fromRelationshipRequest(
        request: CryptoRelationshipPublicRequest,
        templateExchangeKeypair: CryptoExchangeKeypair
    ): Promise<CryptoRelationshipSecretsWithLibsodium> {
        return await this.fromPeerNonce(
            request.exchangeKey,
            request.ephemeralKey,
            request.signatureKey,
            request.nonce,
            templateExchangeKeypair,
            undefined,
            CryptoRelationshipType.Requestor
        );
    }

    /**
     * The "peer nonce" approach – sets up keys & states using ephemeral derivations (libsodium).
     */
    public static async fromPeerNonce(
        peerExchangeKey: CryptoExchangePublicKey,
        peerTemplateKey: CryptoExchangePublicKey,
        peerSignatureKey: CryptoSignaturePublicKey,
        peerGeneratedNonce: CoreBuffer,
        templateExchangeKeypair: CryptoExchangeKeypair,
        peerIdentityKey?: CryptoSignaturePublicKey,
        peerType: CryptoRelationshipType = CryptoRelationshipType.Requestor
    ): Promise<CryptoRelationshipSecrets> {
        const [signatureKeypair, exchangeKeypair] = await Promise.all([
            CryptoSignatures.generateKeypair(),
            CryptoExchange.generateKeypair()
        ]);

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
        const [derivedTx, derivedRx] = await Promise.all([
            CryptoDerivation.deriveKeyFromBase(derivedKey.transmissionKey, 1, "RELTEM01"),
            CryptoDerivation.deriveKeyFromBase(derivedKey.receivingKey, 1, "RELREQ01")
        ]);

        const [receiveState, transmitState] = await Promise.all([
            CryptoPrivateStateReceive.fromNonce(peerGeneratedNonce, derivedRx.secretKey),
            CryptoPrivateStateTransmit.generate(derivedTx.secretKey)
        ]);

        const masterKey = await CryptoExchange.deriveTemplator(templateExchangeKeypair, peerTemplateKey);
        const secretKey = await CryptoDerivation.deriveKeyFromBase(masterKey.receivingKey, 1, "REQTMP01");

        return this.from({
            exchangeKeypair,
            signatureKeypair,
            receiveState,
            transmitState,
            type: ownType,
            peerExchangeKey,
            peerSignatureKey,
            peerTemplateKey,
            peerIdentityKey,
            requestSecretKey: secretKey
        });
    }
}

/**
 * A simple flag indicating if handle-based usage is available.
 */
let relationshipSecretsProviderInitialized = false;

/**
 * Call this during initialization if you have a crypto-layer provider for relationship secrets.
 */
export function initCryptoRelationshipSecrets(): void {
    relationshipSecretsProviderInitialized = true;
}

/**
 * The "unified" class that checks if the object is handle-based and calls the handle-based code if so,
 * or calls libsodium fallback if not.
 */
@type("CryptoRelationshipSecrets")
export class CryptoRelationshipSecrets extends CryptoRelationshipSecretsWithLibsodium {
    public override async sign(content: CoreBuffer, algorithm = CryptoHashAlgorithm.SHA256): Promise<CryptoSignature> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            // Delegate to the handle-based instance
            const handle = this as unknown as CryptoRelationshipSecretsHandle;
            return await handle.sign(content, algorithm);
        }
        return await super.sign(content, algorithm);
    }

    public override async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            return await (this as unknown as CryptoRelationshipSecretsHandle).verifyOwn(content, signature);
        }
        return await super.verifyOwn(content, signature);
    }

    public override async verifyPeer(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            return await (this as unknown as CryptoRelationshipSecretsHandle).verifyPeer(content, signature);
        }
        return await super.verifyPeer(content, signature);
    }

    public override async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            return await (this as unknown as CryptoRelationshipSecretsHandle).verifyPeerIdentity(content, signature);
        }
        return await super.verifyPeerIdentity(content, signature);
    }

    public override async encrypt(content: CoreBuffer): Promise<CryptoCipher> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            return await (this as unknown as CryptoRelationshipSecretsHandle).encrypt(content);
        }
        return await super.encrypt(content);
    }

    public override async decryptOwn(cipher: CryptoCipher): Promise<CoreBuffer> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            return await (this as unknown as CryptoRelationshipSecretsHandle).decryptOwn(cipher);
        }
        return await super.decryptOwn(cipher);
    }

    public override async decryptPeer(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            return await (this as unknown as CryptoRelationshipSecretsHandle).decryptPeer(cipher, omitCounterCheck);
        }
        return await super.decryptPeer(cipher, omitCounterCheck);
    }

    public override async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            return await (this as unknown as CryptoRelationshipSecretsHandle).decryptRequest(cipher);
        }
        return await super.decryptRequest(cipher);
    }

    /**
     * Overridden method: if handle-based, produce a handle-based public response (async).
     * Otherwise, call the libsodium-based method from the parent class.
     */
    public override toPublicResponse(): CryptoRelationshipPublicResponse {
        if (relationshipSecretsProviderInitialized && this.exchangeKeypair instanceof CryptoExchangeKeypairHandle) {
            // If handle-based usage is active, cast to the handle-based secrets class
            // and call its async `toPublicResponse()` method.
            const handle = this as unknown as CryptoRelationshipSecretsHandle;
            return handle.toPublicResponse() as unknown as CryptoRelationshipPublicResponse;
        }
        // fallback to the libsodium-based method
        return super.toPublicResponse();
    }

    /**
     * We override fromRelationshipResponse to detect handle-based usage, calling the handle-based method if so.
     */
    public static override async fromRelationshipResponse(
        response: CryptoRelationshipPublicResponse,
        request: CryptoRelationshipRequestSecrets
    ): Promise<CryptoRelationshipSecrets> {
        // If the exchangeKeypair in the request is handle-based, do handle-based
        if (relationshipSecretsProviderInitialized && (request.exchangeKeypair as any)?.keyPairHandle) {
            const handle = await CryptoRelationshipSecretsHandle.fromRelationshipResponse(
                response as unknown as CryptoRelationshipPublicResponseHandle,
                request as unknown as CryptoRelationshipRequestSecretsHandle
            );
            return handle as unknown as CryptoRelationshipSecrets;
        }
        // fallback to libsodium approach
        const baseResult = await super.fromRelationshipResponse(response, request);
        return baseResult as CryptoRelationshipSecrets;
    }

    public static override async fromRelationshipRequest(
        request: CryptoRelationshipPublicRequest,
        templateExchangeKeypair: CryptoExchangeKeypair
    ): Promise<CryptoRelationshipSecrets> {
        if (relationshipSecretsProviderInitialized && (templateExchangeKeypair as any)?.keyPairHandle) {
            const handle = await CryptoRelationshipSecretsHandle.fromRelationshipRequest(
                request as unknown as CryptoRelationshipPublicRequestHandle,
                templateExchangeKeypair as unknown as CryptoExchangeKeypairHandle
            );
            return handle as unknown as CryptoRelationshipSecrets;
        }
        return await super.fromRelationshipRequest(request, templateExchangeKeypair);
    }

    public static override async fromPeerNonce(
        peerExchangeKey: CryptoExchangePublicKey,
        peerTemplateKey: CryptoExchangePublicKey,
        peerSignatureKey: CryptoSignaturePublicKey,
        peerGeneratedNonce: CoreBuffer,
        templateExchangeKeypair: CryptoExchangeKeypair,
        peerIdentityKey?: CryptoSignaturePublicKey,
        peerType: CryptoRelationshipType = CryptoRelationshipType.Requestor
    ): Promise<CryptoRelationshipSecrets> {
        if (relationshipSecretsProviderInitialized && (templateExchangeKeypair as any)?.keyPairHandle) {
            const handle = await CryptoRelationshipSecretsHandle.fromPeerNonce(
                peerExchangeKey as unknown as CryptoExchangePublicKeyHandle,
                peerTemplateKey as unknown as CryptoExchangePublicKeyHandle,
                peerSignatureKey as unknown as CryptoSignaturePublicKeyHandle,
                peerGeneratedNonce,
                templateExchangeKeypair as unknown as CryptoExchangeKeypairHandle,
                peerIdentityKey as unknown as CryptoSignaturePublicKeyHandle,
                peerType
            );
            return handle as unknown as CryptoRelationshipSecrets;
        }
        const baseResult = await super.fromPeerNonce(
            peerExchangeKey,
            peerTemplateKey,
            peerSignatureKey,
            peerGeneratedNonce,
            templateExchangeKeypair,
            peerIdentityKey,
            peerType
        );
        return CryptoRelationshipSecrets.from(baseResult);
    }
}
