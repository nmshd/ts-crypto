import { SerializableAsync } from "@js-soft/ts-serval";
import {
    CoreBuffer,
    CryptoDerivation,
    CryptoEncryptionAlgorithm,
    CryptoExchange,
    CryptoExchangeAlgorithm,
    CryptoExchangeKeypair,
    CryptoExchangePrivateKey,
    CryptoExchangePublicKey,
    CryptoExchangeSecrets,
    CryptoPrivateKey,
    CryptoPublicKey
} from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoExchangeTest {
    public static run(): void {
        describe("CryptoExchange", function () {
            describe("Execute generateKeypair() with ECDH_X25519", function () {
                let keypair: CryptoExchangeKeypair;
                before(async function () {
                    keypair = await CryptoExchange.generateKeypair(CryptoExchangeAlgorithm.ECDH_X25519);
                });

                it("should return a CryptoPrivateKey as privateKey", function () {
                    expect(keypair.privateKey).to.exist;
                    expect(keypair.privateKey).to.be.instanceOf(CryptoPrivateKey);
                    expect(keypair.privateKey.algorithm).to.exist;
                    expect(keypair.privateKey.privateKey).to.exist;
                });

                it("should return a CryptoPublicKey as publicKey", function () {
                    expect(keypair.publicKey).to.exist;
                    expect(keypair.publicKey).to.be.instanceOf(CryptoPublicKey);
                    expect(keypair.publicKey.algorithm).to.exist;
                    expect(keypair.publicKey.publicKey).to.exist;
                });

                it("should return a correct public key out of the private key", async function () {
                    const publicKey = await keypair.privateKey.toPublicKey();
                    expect(publicKey.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                });

                it("should return a correct algorithms in the keys", function () {
                    expect(keypair.privateKey.algorithm).to.be.equal(CryptoExchangeAlgorithm.ECDH_X25519);
                    expect(keypair.publicKey.algorithm).to.be.equal(CryptoExchangeAlgorithm.ECDH_X25519);
                });

                it("should serialize and deserialize signature public keys", async function () {
                    const serialized = keypair.publicKey.serialize();
                    const deserialized = await CryptoExchangePublicKey.deserialize(serialized);
                    expect(deserialized.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.publicKey.algorithm);
                });

                it("should serialize and deserialize signature private keys", async function () {
                    const serialized = keypair.privateKey.serialize();
                    const deserialized = await CryptoExchangePrivateKey.deserialize(serialized);
                    expect(deserialized.privateKey.toBase64URL()).equals(keypair.privateKey.privateKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.privateKey.algorithm);
                });

                it("should serialize and deserialize signature keypairs", async function () {
                    const serialized = keypair.serialize();
                    const deserialized = await CryptoExchangeKeypair.deserialize(serialized);
                    expect(deserialized.privateKey.privateKey.toBase64URL()).equals(
                        keypair.privateKey.privateKey.toBase64URL()
                    );
                    expect(deserialized.publicKey.publicKey.toBase64URL()).equals(
                        keypair.publicKey.publicKey.toBase64URL()
                    );
                });

                it("should convert signature public keys to base64 and back again", async function () {
                    const serialized = keypair.publicKey.toBase64();
                    const deserialized = await CryptoExchangePublicKey.fromBase64(serialized);
                    expect(deserialized.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.publicKey.algorithm);
                });

                it("should convert signature private keys to base64 and back again", async function () {
                    const serialized = keypair.privateKey.toBase64();
                    const deserialized = await CryptoExchangePrivateKey.fromBase64(serialized);
                    expect(deserialized.privateKey.toBase64URL()).equals(keypair.privateKey.privateKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.privateKey.algorithm);
                });

                it("should convert signature keypairs to base64 and back again", async function () {
                    const serialized = keypair.toBase64();
                    const deserialized = await CryptoExchangeKeypair.fromBase64(serialized);
                    expect(deserialized.privateKey.privateKey.toBase64URL()).equals(
                        keypair.privateKey.privateKey.toBase64URL()
                    );
                    expect(deserialized.publicKey.publicKey.toBase64URL()).equals(
                        keypair.publicKey.publicKey.toBase64URL()
                    );
                });

                it("should serialize and deserialize signature public keys from @type", async function () {
                    const serialized = keypair.publicKey.serialize();
                    const deserialized = (await SerializableAsync.deserializeUnknown(
                        serialized
                    )) as CryptoExchangePublicKey;
                    expect(deserialized).instanceOf(CryptoExchangePublicKey);
                    expect(deserialized.publicKey.toBase64URL()).equals(keypair.publicKey.publicKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.publicKey.algorithm);
                });

                it("should serialize and deserialize signature private keys from @type", async function () {
                    const serialized = keypair.privateKey.serialize();
                    const deserialized = (await SerializableAsync.deserializeUnknown(
                        serialized
                    )) as CryptoExchangePrivateKey;
                    expect(deserialized).instanceOf(CryptoExchangePrivateKey);
                    expect(deserialized.privateKey.toBase64URL()).equals(keypair.privateKey.privateKey.toBase64URL());
                    expect(deserialized.algorithm).equals(keypair.privateKey.algorithm);
                });

                it("should serialize and deserialize signature keypairs from @type", async function () {
                    const serialized = keypair.serialize();
                    const deserialized = (await SerializableAsync.deserializeUnknown(
                        serialized
                    )) as CryptoExchangeKeypair;
                    expect(deserialized).instanceOf(CryptoExchangeKeypair);
                    expect(deserialized.privateKey.privateKey.toBase64URL()).equals(
                        keypair.privateKey.privateKey.toBase64URL()
                    );
                    expect(deserialized.publicKey.publicKey.toBase64URL()).equals(
                        keypair.publicKey.publicKey.toBase64URL()
                    );
                });
            });

            describe("Execute deriveTo() and deriveFrom() with X25519", function () {
                const asymmetric = CryptoExchangeAlgorithm.ECDH_X25519;
                const symmetric = CryptoEncryptionAlgorithm.AES256_GCM;

                let sender: CryptoExchangeKeypair;
                let recipient: CryptoExchangeKeypair;

                let secret1: CoreBuffer;
                let secretsSender: CryptoExchangeSecrets;

                before(async function () {
                    sender = await CryptoExchange.generateKeypair(asymmetric);
                    recipient = await CryptoExchange.generateKeypair(asymmetric);
                });

                it("should create equal client and server keys", async function () {
                    const senderPub = (await CryptoPublicKey.fromString(
                        sender.publicKey.toString(),
                        asymmetric
                    )) as CryptoExchangePublicKey;
                    const recipientPub = (await CryptoPublicKey.fromString(
                        recipient.publicKey.toString(),
                        asymmetric
                    )) as CryptoExchangePublicKey;

                    const client = await CryptoExchangeKeypair.fromJSON({
                        prv: sender.privateKey.toJSON(),
                        pub: sender.publicKey.toJSON()
                    });

                    const server = await CryptoExchangeKeypair.fromJSON({
                        prv: recipient.privateKey.toJSON(),
                        pub: recipient.publicKey.toJSON()
                    });

                    const clientKeys = await CryptoExchange.deriveTemplator(client, recipientPub, symmetric);
                    secretsSender = clientKeys;

                    const serverKeys2 = await CryptoExchange.deriveRequestor(client, recipientPub, symmetric);

                    const clientKeys2 = await CryptoExchange.deriveTemplator(server, senderPub, symmetric);

                    secret1 = clientKeys.transmissionKey;

                    expect(clientKeys2.transmissionKey.toBase64URL()).equals(serverKeys2.receivingKey.toBase64URL());
                    expect(clientKeys2.receivingKey.toBase64URL()).equals(serverKeys2.transmissionKey.toBase64URL());

                    expect(clientKeys2.transmissionKey.toBase64URL()).equals(serverKeys2.receivingKey.toBase64URL());
                    expect(clientKeys2.receivingKey.toBase64URL()).equals(serverKeys2.transmissionKey.toBase64URL());
                });

                it("should serialize and deserialize the sender's secrets", async function () {
                    const serialized = secretsSender.serialize();
                    const deserialized = await CryptoExchangeSecrets.deserialize(serialized);
                    expect(deserialized.receivingKey.toBase64URL()).equals(secretsSender.receivingKey.toBase64URL());
                    expect(deserialized.transmissionKey.toBase64URL()).equals(
                        secretsSender.transmissionKey.toBase64URL()
                    );
                });

                it("should serialize and deserialize the sender's secrets from @type", async function () {
                    const serialized = secretsSender.serialize();
                    const deserialized = (await SerializableAsync.deserializeUnknown(
                        serialized
                    )) as CryptoExchangeSecrets;
                    expect(deserialized).instanceOf(CryptoExchangeSecrets);
                    expect(deserialized.receivingKey.toBase64URL()).equals(secretsSender.receivingKey.toBase64URL());
                    expect(deserialized.transmissionKey.toBase64URL()).equals(
                        secretsSender.transmissionKey.toBase64URL()
                    );
                });

                it("should derive equal keys", async function () {
                    secret1 = CoreBuffer.fromBase64("cLlKsiIdMeFDvd03F6htbz2A+/sRL4uzRXrjxve/oo8=");

                    async function testIt(
                        secret: CoreBuffer,
                        context: string,
                        keyId: number,
                        expected = "",
                        iterations = 20
                    ) {
                        for (let i = 0, l = iterations; i < l; i++) {
                            const derived = await CryptoDerivation.deriveKeyFromBase(secret, keyId, context);
                            const b64 = derived.secretKey.toBase64URL();
                            if (expected) {
                                expect(b64).to.equal(expected);
                            }
                        }
                    }
                    await testIt(secret1, "8chars!!", 0, "o73hWVbWNfe6l9o5Wyntdl8gFvabrWG9kJyW1kofFbA", 10);
                    await testIt(secret1, "8chars!!", 1, "PuIM7NhJlfU6IYyr_AMswpGMDyzHtEnFfmuq32mNHxA", 10);
                    await testIt(secret1, "8chars!!", 2, "YS621H7sQTqlq4usymQ9wMtgxsIvaOob0GX4gJQSRUY", 10);
                    await testIt(secret1, "8chars!!", 3, "V1zihdRYJ2OSXcTDouhu8cTWMQ8-ixk0ZA3GdBHfxn0", 10);
                    await testIt(secret1, "8chars!!", 4, "K7Sd9iFy-lfHfxJ62WtVC9Kg-Z1osVgg4ycS-w4H33Q", 10);
                });
            });

            describe("Execute deriveSecret() with ECDH_X25519", function () {
                // TODO: JSSNMSHDD-2513 (we should either test this or remove the functionality from the public api - otherwise potentially untested functionality could be used)
            });
        });
    }
}