import { Serializable } from "@js-soft/ts-serval";
import {
    CoreBuffer,
    CryptoCipher,
    CryptoError,
    CryptoExchange,
    CryptoExchangeKeypair,
    CryptoExchangePublicKey,
    CryptoRelationshipPublicRequest,
    CryptoRelationshipPublicResponse,
    CryptoRelationshipRequestSecrets,
    CryptoRelationshipSecrets,
    CryptoSignatureKeypair,
    CryptoSignaturePublicKey,
    CryptoSignatures
} from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoRelationshipTest {
    public static testRelationshipSecrets(
        requestorRelationship: CryptoRelationshipSecrets,
        templatorRelationship: CryptoRelationshipSecrets
    ): void {
        expect(requestorRelationship.peerExchangeKey.publicKey.toBase64URL()).equals(
            templatorRelationship.exchangeKeypair.publicKey.publicKey.toBase64URL(),
            "requestor.peerExchangeKey !== templatorRelationship.exchangeKey"
        );
        expect(requestorRelationship.peerSignatureKey.publicKey.toBase64URL()).equals(
            templatorRelationship.signatureKeypair.publicKey.publicKey.toBase64URL(),
            "requestor.peerSignatureKey !== templatorRelationship.signatureKey"
        );
        expect(requestorRelationship.signatureKeypair.publicKey.publicKey.toBase64URL()).equals(
            templatorRelationship.peerSignatureKey.publicKey.toBase64URL(),
            "requestor.signaturePublicKey !== templatorRelationship.peerSignatureKey"
        );
        expect(requestorRelationship.exchangeKeypair.publicKey.publicKey.toBase64URL()).equals(
            templatorRelationship.peerExchangeKey.publicKey.toBase64URL(),
            "requestor.exchangePublicKey !== templatorRelationship.peerExchangeKey"
        );

        expect(requestorRelationship.transmitState.nonce.toBase64URL()).equals(
            templatorRelationship.receiveState.nonce.toBase64URL(),
            "requestor.transmitStateNonce !== templator.receiveStateNonce"
        );
        expect(requestorRelationship.transmitState.secretKey.toBase64URL()).equals(
            templatorRelationship.receiveState.secretKey.toBase64URL(),
            "requestor.transmitStateKey !== templator.receiveStateKey"
        );
        expect(requestorRelationship.transmitState.counter).equals(
            templatorRelationship.receiveState.counter,
            "requestor.transmitStateCounter !== templator.receiveStateCounter"
        );
        expect(requestorRelationship.receiveState.secretKey.toBase64URL()).equals(
            templatorRelationship.transmitState.secretKey.toBase64URL(),
            "requestor.receiveStateKey !== templator.transmitStateKey"
        );
        expect(requestorRelationship.receiveState.nonce.toBase64URL()).equals(
            templatorRelationship.transmitState.nonce.toBase64URL(),
            "requestor.receiveStateNonce !== templator.transmitStateNonce"
        );
        expect(requestorRelationship.receiveState.counter).equals(
            templatorRelationship.transmitState.counter,
            "requestor.receiveStateCounter !== templator.transmitStateCounter"
        );
    }

    public static run(): void {
        describe("CryptoRelationship", function () {
            let templatorIdentity: CryptoSignatureKeypair;
            let templatorIdentityPublicKey: CryptoSignaturePublicKey;
            let templatorTemplateExchangeKey: CryptoExchangeKeypair;
            let templatorTemplateExchangePublicKey: CryptoExchangePublicKey;
            let request: CryptoRelationshipRequestSecrets;
            let publicRequest: CryptoRelationshipPublicRequest;
            let requestCipher: CryptoCipher;
            let responseCipher: CryptoCipher;
            let templatorRelationship: CryptoRelationshipSecrets;
            let publicResponse: CryptoRelationshipPublicResponse;
            let requestorRelationship: CryptoRelationshipSecrets;
            let templatorCiphers: CryptoCipher[];
            let requestorCiphers: CryptoCipher[];

            before(async function () {
                templatorIdentity = await CryptoSignatures.generateKeypair();
                templatorIdentityPublicKey = templatorIdentity.publicKey;
                templatorTemplateExchangeKey = await CryptoExchange.generateKeypair();
                templatorTemplateExchangePublicKey = templatorTemplateExchangeKey.publicKey;
                templatorCiphers = [];
                requestorCiphers = [];
            });

            it("should create a relationship request crypto object", async function () {
                request = await CryptoRelationshipRequestSecrets.fromPeer(
                    templatorTemplateExchangePublicKey,
                    templatorIdentityPublicKey
                );
                expect(request).to.exist;
                expect(request.nonce).to.exist;
                expect(request.nonce.buffer.byteLength).to.be.equal(24);
                expect(request.secretKey).to.exist;
                expect(request.secretKey.secretKey.buffer.byteLength).to.be.equal(32);

                expect(request.peerExchangeKey).to.exist;
                expect(request.peerIdentityKey).to.exist;
                expect(request.exchangeKeypair).to.exist;
                expect(request.ephemeralKeypair).to.exist;
                expect(request.signatureKeypair).to.exist;
            });

            it("should serialize and deserialize a relationship request crypto object", function () {
                const serialized = request.serialize();
                const deserialized = CryptoRelationshipRequestSecrets.deserialize(serialized);
                expect(deserialized.peerIdentityKey.toBase64()).equals(request.peerIdentityKey.toBase64());
                expect(deserialized.secretKey.toBase64()).equals(request.secretKey.toBase64());
                expect(deserialized.signatureKeypair.toBase64()).equals(request.signatureKeypair.toBase64());
                expect(deserialized.ephemeralKeypair.toBase64()).equals(request.ephemeralKeypair.toBase64());
                expect(deserialized.exchangeKeypair.toBase64()).equals(request.exchangeKeypair.toBase64());
                expect(deserialized.nonce.toBase64()).equals(request.nonce.toBase64());
                expect(deserialized.peerExchangeKey.toBase64()).equals(request.peerExchangeKey.toBase64());
            });

            it("should serialize and deserialize a relationship request crypto object from @type", function () {
                const serialized = request.serialize();
                const deserialized = Serializable.deserializeUnknown(serialized) as CryptoRelationshipRequestSecrets;
                expect(deserialized).instanceOf(CryptoRelationshipRequestSecrets);
                expect(deserialized.peerIdentityKey.toBase64()).equals(request.peerIdentityKey.toBase64());
                expect(deserialized.secretKey.toBase64()).equals(request.secretKey.toBase64());
                expect(deserialized.signatureKeypair.toBase64()).equals(request.signatureKeypair.toBase64());
                expect(deserialized.ephemeralKeypair.toBase64()).equals(request.ephemeralKeypair.toBase64());
                expect(deserialized.exchangeKeypair.toBase64()).equals(request.exchangeKeypair.toBase64());
                expect(deserialized.nonce.toBase64()).equals(request.nonce.toBase64());
                expect(deserialized.peerExchangeKey.toBase64()).equals(request.peerExchangeKey.toBase64());
            });

            it("requestor should encrypt request", async function () {
                request = await CryptoRelationshipRequestSecrets.fromPeer(
                    templatorTemplateExchangePublicKey,
                    templatorIdentityPublicKey
                );
                publicRequest = request.toPublicRequest();
                expect(publicRequest).to.exist;
                expect(publicRequest.signatureKey).to.exist;
                expect(publicRequest.exchangeKey).to.exist;
                expect(publicRequest.nonce).to.exist;

                const content = CoreBuffer.fromUtf8("RelationshipRequest");
                requestCipher = await request.encryptRequest(content);
                expect(requestCipher).to.exist;
                expect(requestCipher.cipher).to.exist;
            });

            it("templator should decrypt request and encrypt response", async function () {
                templatorRelationship = await CryptoRelationshipSecrets.fromRelationshipRequest(
                    publicRequest,
                    templatorTemplateExchangeKey
                );
                publicResponse = templatorRelationship.toPublicResponse();
                expect(publicResponse).to.exist;
                expect(publicResponse.exchangeKey).to.exist;
                expect(publicResponse.signatureKey).to.exist;
                expect(publicResponse.state).to.exist;

                expect(publicRequest.signatureKey.publicKey.toBase64URL()).equals(
                    templatorRelationship.peerSignatureKey.publicKey.toBase64URL(),
                    "publicRequest.signatureKey !== templatorRelationship.peerSignatureKey"
                );

                expect(publicRequest.exchangeKey.publicKey.toBase64URL()).equals(
                    templatorRelationship.peerExchangeKey.publicKey.toBase64URL(),
                    "publicRequest.exchangeKey !== templatorRelationship.peerExchangeKey"
                );

                const plaintext = await templatorRelationship.decryptRequest(requestCipher);
                expect(plaintext.toUtf8()).to.equal("RelationshipRequest");

                const content = CoreBuffer.fromUtf8("RelationshipResponse");
                responseCipher = await templatorRelationship.encrypt(content);
            });

            it("should serialize and deserialize a relationship secrets object", function () {
                const serialized = templatorRelationship.serialize();
                const deserialized = CryptoRelationshipSecrets.deserialize(serialized);
                expect(deserialized.peerSignatureKey.toBase64()).equals(
                    templatorRelationship.peerSignatureKey.toBase64()
                );
                expect(deserialized.peerExchangeKey.toBase64()).equals(
                    templatorRelationship.peerExchangeKey.toBase64()
                );
                expect(deserialized.signatureKeypair.toBase64()).equals(
                    templatorRelationship.signatureKeypair.toBase64()
                );
                expect(deserialized.requestSecretKey.toBase64()).equals(
                    templatorRelationship.requestSecretKey.toBase64()
                );
                expect(deserialized.exchangeKeypair.toBase64()).equals(
                    templatorRelationship.exchangeKeypair.toBase64()
                );
                expect(deserialized.type).equals(templatorRelationship.type);
                expect(deserialized.peerTemplateKey.toBase64()).equals(
                    templatorRelationship.peerTemplateKey.toBase64()
                );
                expect(deserialized.receiveState.serialize()).equals(templatorRelationship.receiveState.serialize());
                expect(deserialized.transmitState.serialize()).equals(templatorRelationship.transmitState.serialize());
            });

            it("should serialize and deserialize a relationship secrets object from @type", function () {
                const serialized = templatorRelationship.serialize();
                const deserialized = Serializable.deserializeUnknown(serialized) as CryptoRelationshipSecrets;
                expect(deserialized).instanceOf(CryptoRelationshipSecrets);
                expect(deserialized.peerSignatureKey.toBase64()).equals(
                    templatorRelationship.peerSignatureKey.toBase64()
                );
                expect(deserialized.peerExchangeKey.toBase64()).equals(
                    templatorRelationship.peerExchangeKey.toBase64()
                );
                expect(deserialized.signatureKeypair.toBase64()).equals(
                    templatorRelationship.signatureKeypair.toBase64()
                );
                expect(deserialized.requestSecretKey.toBase64()).equals(
                    templatorRelationship.requestSecretKey.toBase64()
                );
                expect(deserialized.exchangeKeypair.toBase64()).equals(
                    templatorRelationship.exchangeKeypair.toBase64()
                );
                expect(deserialized.type).equals(templatorRelationship.type);
                expect(deserialized.peerTemplateKey.toBase64()).equals(
                    templatorRelationship.peerTemplateKey.toBase64()
                );
                expect(deserialized.receiveState.serialize()).equals(templatorRelationship.receiveState.serialize());
                expect(deserialized.transmitState.serialize()).equals(templatorRelationship.transmitState.serialize());
            });

            it("requestor should create Relationship", async function () {
                requestorRelationship = await CryptoRelationshipSecrets.fromRelationshipResponse(
                    publicResponse,
                    request
                );
                expect(requestorRelationship).to.exist;

                const plaintext = await requestorRelationship.decryptPeer(responseCipher);
                expect(plaintext.toUtf8()).to.equal("RelationshipResponse");

                CryptoRelationshipTest.testRelationshipSecrets(requestorRelationship, templatorRelationship);
            });

            it("templator should create ciphers", async function () {
                for (let i = 0; i < 10; i++) {
                    const message = CoreBuffer.fromUtf8(`TemplatorSent${i}`);
                    templatorCiphers.push(await templatorRelationship.encrypt(message));
                }
                expect(templatorCiphers.length).equals(10);
            });

            it("requestor should create ciphers", async function () {
                for (let i = 0; i < 10; i++) {
                    const message = CoreBuffer.fromUtf8(`RequestorSent${i}`);
                    requestorCiphers.push(await requestorRelationship.encrypt(message));
                }
                expect(requestorCiphers.length).equals(10);
            });

            it("templator should decrypt requestor's ciphers", async function () {
                for (let i = 0; i < 10; i++) {
                    const cipher = requestorCiphers[i];
                    const message = CoreBuffer.fromUtf8(`RequestorSent${i}`);
                    const plaintext = await templatorRelationship.decryptPeer(cipher);
                    expect(plaintext.equals(message)).to.be.true;
                }
            });

            it("requestor should decrypt templator's ciphers", async function () {
                for (let i = 0; i < 10; i++) {
                    const cipher = templatorCiphers[i];
                    const message = CoreBuffer.fromUtf8(`TemplatorSent${i}`);
                    const plaintext = await requestorRelationship.decryptPeer(cipher);
                    expect(plaintext.equals(message)).to.be.true;
                }
            });

            it("templator should not be able to decrypt requestor's ciphers out of order", async function () {
                let error;
                try {
                    const cipher = requestorCiphers[0];
                    await templatorRelationship.decryptPeer(cipher);
                } catch (e: any) {
                    error = e;
                }

                expect(error).to.exist;
                expect(error).to.be.instanceOf(Error);
                expect(error).to.be.instanceOf(CryptoError);
                expect(error.code).to.equal("error.crypto.state.orderDoesNotMatch");
            });

            it("requestor should not be able to decrypt templator's ciphers out of order", async function () {
                let error;
                try {
                    const cipher = templatorCiphers[0];
                    await requestorRelationship.decryptPeer(cipher);
                } catch (e: any) {
                    error = e;
                }

                expect(error).to.exist;
                expect(error).to.be.instanceOf(Error);
                expect(error).to.be.instanceOf(CryptoError);
                expect(error.code).to.equal("error.crypto.state.orderDoesNotMatch");
            });

            it("templator should decrypt requestor's ciphers (omit order)", async function () {
                for (let i = 0; i < 10; i++) {
                    const cipher = requestorCiphers[i];
                    const message = CoreBuffer.fromUtf8(`RequestorSent${i}`);
                    const plaintext = await templatorRelationship.decryptPeer(cipher, true);
                    expect(plaintext.equals(message)).to.be.true;
                }
            });

            it("requestor should decrypt templator's ciphers (omit order)", async function () {
                for (let i = 0; i < 10; i++) {
                    const cipher = templatorCiphers[i];
                    const message = CoreBuffer.fromUtf8(`TemplatorSent${i}`);
                    const plaintext = await requestorRelationship.decryptPeer(cipher, true);
                    expect(plaintext.equals(message)).to.be.true;
                }
            });

            it("templator should decrypt own ciphers", async function () {
                for (let i = 0; i < 10; i++) {
                    const cipher = templatorCiphers[i];
                    const message = CoreBuffer.fromUtf8(`TemplatorSent${i}`);
                    const plaintext = await templatorRelationship.decryptOwn(cipher);
                    expect(plaintext.equals(message)).to.be.true;
                }
            });

            it("requestor should decrypt own ciphers", async function () {
                for (let i = 0; i < 10; i++) {
                    const cipher = requestorCiphers[i];
                    const message = CoreBuffer.fromUtf8(`RequestorSent${i}`);
                    const plaintext = await requestorRelationship.decryptOwn(cipher);
                    expect(plaintext.equals(message)).to.be.true;
                }
            });
        });
    }
}
