import { ISerializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoDerivation } from "../CryptoDerivation";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption, CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoSecretKey, ICryptoSecretKey } from "../encryption/CryptoSecretKey";
import { CryptoExchange } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypair, ICryptoExchangeKeypair } from "../exchange/CryptoExchangeKeypair";
import { CryptoExchangePublicKey, ICryptoExchangePublicKey } from "../exchange/CryptoExchangePublicKey";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignatureKeypair, ICryptoSignatureKeypair } from "../signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKey, ICryptoSignaturePublicKey } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { ICryptoPrivateState } from "../state/CryptoPrivateState";
import { CryptoPrivateStateReceive } from "../state/CryptoPrivateStateReceive";
import { CryptoPrivateStateTransmit } from "../state/CryptoPrivateStateTransmit";
import { CryptoStateType } from "../state/CryptoStateType";
import { CryptoRelationshipPublicRequest } from "./CryptoRelationshipPublicRequest";
import { CryptoRelationshipPublicResponse } from "./CryptoRelationshipPublicResponse";
import { CryptoRelationshipRequestSecrets } from "./CryptoRelationshipRequestSecrets";
import { CryptoRelationshipType } from "./CryptoRelationshipType";

export interface ICryptoRelationshipSecrets extends ISerializable {
    id?: string;
    type: CryptoRelationshipType;
    exchangeKeypair: ICryptoExchangeKeypair;
    signatureKeypair: ICryptoSignatureKeypair;
    transmitState: ICryptoPrivateState;
    receiveState: ICryptoPrivateState;
    peerExchangeKey: ICryptoExchangePublicKey;
    peerSignatureKey: ICryptoSignaturePublicKey;
    peerTemplateKey: ICryptoExchangePublicKey;
    peerIdentityKey?: ICryptoSignaturePublicKey;
    requestSecretKey: ICryptoSecretKey;
}

@type("CryptoRelationshipSecrets")
export class CryptoRelationshipSecrets extends CryptoSerializable implements ICryptoRelationshipSecrets {
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

    public static from(value: ICryptoRelationshipSecrets): CryptoRelationshipSecrets {
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
                "The peer of this relationship is not set. You have to initialize this relationship with a peer first."
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
        return CryptoRelationshipPublicResponse.from({
            exchangeKey: this.exchangeKeypair.publicKey,
            signatureKey: this.signatureKeypair.publicKey,
            state: this.transmitState.toPublicState()
        });
    }

    public static async fromRelationshipResponse(
        response: CryptoRelationshipPublicResponse,
        request: CryptoRelationshipRequestSecrets
    ): Promise<CryptoRelationshipSecrets> {
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

    public static async fromRelationshipRequest(
        request: CryptoRelationshipPublicRequest,
        templateExchangeKeypair: CryptoExchangeKeypair
    ): Promise<CryptoRelationshipSecrets> {
        return await CryptoRelationshipSecrets.fromPeerNonce(
            request.exchangeKey,
            request.ephemeralKey,
            request.signatureKey,
            request.nonce,
            templateExchangeKeypair,
            undefined,
            CryptoRelationshipType.Requestor
        );
    }

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
}
