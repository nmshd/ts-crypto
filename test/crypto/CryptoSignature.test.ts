import { Serializable } from "@js-soft/ts-serval";
import {
    CoreBuffer,
    CryptoHashAlgorithm,
    CryptoSignature,
    CryptoSignatureAlgorithm,
    CryptoSignatureKeypair,
    CryptoSignaturePrivateKey,
    CryptoSignaturePublicKey,
    CryptoSignatures,
    Encoding
} from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoSignatureTest {
    public static run(): void {
        describe("CryptoSignature", function () {
            describe("Execute generateKeypair() with ECDSA_ED25519", function () {
                let keypair: CryptoSignatureKeypair;
                before(async function () {
                    keypair = await CryptoSignatures.generateKeypair(CryptoSignatureAlgorithm.ECDSA_ED25519);
                });

                it("should return a CryptoPrivateKey as privateKey", function () {
                    expect(keypair.privateKey).to.exist;
                    expect(keypair.privateKey).to.be.instanceOf(CryptoSignaturePrivateKey);
                    expect(keypair.privateKey.algorithm).to.exist;
                    expect(keypair.privateKey.privateKey).to.exist;
                });

                it("should return a CryptoPublicKey as publicKey", function () {
                    expect(keypair.publicKey).to.exist;
                    expect(keypair.publicKey).to.be.instanceOf(CryptoSignaturePublicKey);
                    expect(keypair.publicKey.algorithm).to.exist;
                    expect(keypair.publicKey.publicKey).to.exist;
                });

                it("should return a correct algorithms in the keys", function () {
                    expect(keypair.privateKey.algorithm).to.be.equal(CryptoSignatureAlgorithm.ECDSA_ED25519);
                    expect(keypair.publicKey.algorithm).to.be.equal(CryptoSignatureAlgorithm.ECDSA_ED25519);
                });

                it("should return a correct public key out of the private key", async function () {
                    const publicKey = await keypair.privateKey.toPublicKey();
                    expect(publicKey.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                });

                it("should serialize and deserialize signature public keys", function () {
                    const serialized = keypair.publicKey.serialize();
                    const deserialized = CryptoSignaturePublicKey.deserialize(serialized);
                    expect(deserialized.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.publicKey.algorithm);
                });

                it("should serialize and deserialize signature private keys", function () {
                    const serialized = keypair.privateKey.serialize();
                    const deserialized = CryptoSignaturePrivateKey.deserialize(serialized);
                    expect(deserialized.privateKey.toBase64URL()).equals(keypair.privateKey.privateKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.privateKey.algorithm);
                });

                it("should serialize and deserialize signature keypairs", function () {
                    const serialized = keypair.serialize();
                    const deserialized = CryptoSignatureKeypair.deserialize(serialized);
                    expect(deserialized.privateKey.privateKey.toBase64URL()).equals(
                        keypair.privateKey.privateKey.toBase64URL()
                    );
                    expect(deserialized.publicKey.publicKey.toBase64URL()).equals(
                        keypair.publicKey.publicKey.toBase64URL()
                    );
                });

                it("should convert signature public keys to base64 and back again", function () {
                    const serialized = keypair.publicKey.toBase64();
                    const deserialized = CryptoSignaturePublicKey.fromBase64(serialized);
                    expect(deserialized.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.publicKey.algorithm);
                });

                it("should convert signature private keys to base64 and back again", function () {
                    const serialized = keypair.privateKey.toBase64();
                    const deserialized = CryptoSignaturePrivateKey.fromBase64(serialized);
                    expect(deserialized.privateKey.toBase64URL()).equals(keypair.privateKey.privateKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.privateKey.algorithm);
                });

                it("should convert signature keypairs to base64 and back again", function () {
                    const serialized = keypair.toBase64();
                    const deserialized = CryptoSignatureKeypair.fromBase64(serialized);
                    expect(deserialized.privateKey.privateKey.toBase64URL()).equals(
                        keypair.privateKey.privateKey.toBase64URL()
                    );
                    expect(deserialized.publicKey.publicKey.toBase64URL()).equals(
                        keypair.publicKey.publicKey.toBase64URL()
                    );
                });

                it("should serialize and deserialize signature public keys from @type", function () {
                    const serialized = keypair.publicKey.serialize();
                    const deserialized = Serializable.deserializeUnknown(serialized) as CryptoSignaturePublicKey;
                    expect(deserialized).instanceOf(CryptoSignaturePublicKey);
                    expect(deserialized.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.publicKey.algorithm);
                });

                it("should serialize and deserialize signature private keys from @type", function () {
                    const serialized = keypair.privateKey.serialize();
                    const deserialized = Serializable.deserializeUnknown(serialized) as CryptoSignaturePrivateKey;
                    expect(deserialized).instanceOf(CryptoSignaturePrivateKey);
                    expect(deserialized.privateKey.toBase64URL()).equals(keypair.privateKey.privateKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.privateKey.algorithm);
                });

                it("should serialize and deserialize signature keypairs from @type", function () {
                    const serialized = keypair.serialize();
                    const deserialized = Serializable.deserializeUnknown(serialized) as CryptoSignatureKeypair;
                    expect(deserialized).instanceOf(CryptoSignatureKeypair);
                    expect(deserialized.privateKey.privateKey.toBase64URL()).equals(
                        keypair.privateKey.privateKey.toBase64URL()
                    );
                    expect(deserialized.publicKey.publicKey.toBase64URL()).equals(
                        keypair.publicKey.publicKey.toBase64URL()
                    );
                });
            });

            describe("Execute sign() with ECDSA_ED25519 SHA512", function () {
                const asymmetric = CryptoSignatureAlgorithm.ECDSA_ED25519;
                const hash = CryptoHashAlgorithm.SHA512;
                const message = "Test";
                const buffer = CoreBuffer.fromString(message, Encoding.Utf8);

                let sender: CryptoSignatureKeypair;

                let signature1: CryptoSignature;
                let signature2: CryptoSignature;
                let signature3: CryptoSignature;

                before(async function () {
                    sender = await CryptoSignatures.generateKeypair(asymmetric);
                });

                it("should return with a CryptoSignature", async function () {
                    const signature = await CryptoSignatures.sign(buffer, sender.privateKey, hash);
                    expect(signature).to.exist;
                    expect(signature).to.be.instanceOf(CryptoSignature);
                });

                it("should return with the correct algorithm", async function () {
                    const signature = await CryptoSignatures.sign(buffer, sender.privateKey, hash);
                    expect(signature.algorithm).to.be.equal(hash);
                });

                it("should create signatures", async function () {
                    signature1 = await CryptoSignatures.sign(buffer, sender.privateKey, hash);
                    signature2 = await CryptoSignatures.sign(buffer, sender.privateKey, hash);
                    signature3 = await CryptoSignatures.sign(buffer, sender.privateKey, hash);
                    expect(signature1).to.exist;
                    expect(signature2).to.exist;
                    expect(signature3).to.exist;
                });

                it("should return valid signatures", async function () {
                    const valid1 = await CryptoSignatures.verify(buffer, signature1, sender.publicKey);
                    expect(valid1).to.be.true;
                    const valid2 = await CryptoSignatures.verify(buffer, signature2, sender.publicKey);
                    expect(valid2).to.be.true;
                    const valid3 = await CryptoSignatures.verify(buffer, signature3, sender.publicKey);
                    expect(valid3).to.be.true;
                });

                it("should serialize and deserialize signatures", async function () {
                    const serialized = signature1.serialize();
                    const deserialized = CryptoSignature.deserialize(serialized);
                    expect(deserialized.signature.toBase64URL()).equals(signature1.signature.toBase64URL());
                    expect(deserialized.algorithm).equals(signature1.algorithm);
                    const valid1 = await CryptoSignatures.verify(buffer, deserialized, sender.publicKey);
                    expect(valid1).to.be.true;
                });
            });

            describe("Execute verify() with ECDSA_ED25519 SHA512", function () {
                const asymmetric = CryptoSignatureAlgorithm.ECDSA_ED25519;
                const hash = CryptoHashAlgorithm.SHA512;
                const message = "Test";
                const buffer = CoreBuffer.fromString(message, Encoding.Utf8);

                let sender: CryptoSignatureKeypair;

                before(async function () {
                    sender = await CryptoSignatures.generateKeypair(asymmetric);
                });

                it("should return with a CryptoSignature", async function () {
                    const signature = await CryptoSignatures.sign(buffer, sender.privateKey, hash);
                    expect(signature).to.exist;
                    expect(signature).to.be.instanceOf(CryptoSignature);
                });

                it("should return with the correct algorithm", async function () {
                    const signature = await CryptoSignatures.sign(buffer, sender.privateKey, hash);
                    expect(signature.algorithm).to.be.equal(hash);
                });
            });
        });
    }
}
