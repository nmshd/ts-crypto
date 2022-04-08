import { Serializable } from "@js-soft/ts-serval";
import {
    CoreBuffer,
    CryptoCipher,
    CryptoEncryption,
    CryptoEncryptionAlgorithm,
    CryptoError,
    CryptoSecretKey
} from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoEncryptionTest {
    public static run(): void {
        describe("CryptoEncryption", function () {
            describe("Execute generateKey() with XCHACHA20_POLY1305", function () {
                let key: CryptoSecretKey;
                before(async function () {
                    key = await CryptoEncryption.generateKey(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                });

                it("should return a SecretKey", function () {
                    expect(key).to.exist;
                    expect(key).to.be.instanceOf(CryptoSecretKey);
                    expect(key.algorithm).to.exist;
                    expect(key.secretKey).to.exist;
                });

                it("should return a correct algorithm in the key", function () {
                    expect(key.algorithm).to.be.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                });

                it("should serialize and deserialize the key correctly", function () {
                    const serialized = key.serialize();
                    const deserialized = CryptoSecretKey.deserialize(serialized);
                    expect(deserialized.secretKey.toBase64URL()).equals(key.secretKey.toBase64URL());
                    expect(deserialized.algorithm).equals(key.algorithm);
                });

                it("should serialize and deserialize the key correctly from @type", function () {
                    const serialized = key.serialize();
                    const deserialized = Serializable.deserializeUnknown(serialized) as CryptoSecretKey;
                    expect(deserialized).instanceOf(CryptoSecretKey);
                    expect(deserialized.secretKey.toBase64URL()).equals(key.secretKey.toBase64URL());
                    expect(deserialized.algorithm).equals(key.algorithm);
                });
            });

            describe("Execute encrypt() with XCHACHA20_POLY1305", function () {
                let key: CryptoSecretKey;
                let key2: CryptoSecretKey;
                const text: CoreBuffer = CoreBuffer.random(4);
                before(async function () {
                    key = await CryptoEncryption.generateKey(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                    key2 = await CryptoEncryption.generateKey(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                });

                it("should return a CryptoCipher with random nonce", async function () {
                    const cipher = await CryptoEncryption.encrypt(text, key);
                    expect(cipher).to.exist;
                    expect(cipher).to.be.instanceOf(CryptoCipher);
                    expect(cipher.algorithm).to.be.equal(key.algorithm);
                    expect(cipher.counter).to.not.exist;
                    expect(cipher.nonce).to.exist;
                    expect(cipher.nonce?.buffer.byteLength).to.equal(24);
                });

                it("should serialize and deserialize the cipher", async function () {
                    const cipher = await CryptoEncryption.encrypt(text, key);

                    const a = CryptoCipher.deserialize(cipher.serialize());
                    expect(a.cipher.toBase64()).equals(cipher.cipher.toBase64());

                    const b = CryptoCipher.fromJSON(cipher.toJSON());
                    expect(b.cipher.toBase64()).equals(cipher.cipher.toBase64());
                });

                it("should serialize and deserialize the cipher from @type", async function () {
                    const cipher = await CryptoEncryption.encrypt(text, key);

                    const serialized = cipher.serialize();
                    const deserialized = Serializable.deserializeUnknown(serialized) as CryptoCipher;
                    expect(deserialized).instanceOf(CryptoCipher);
                    expect(deserialized.cipher.toBase64URL()).equals(cipher.cipher.toBase64URL());
                    expect(deserialized.counter).equals(cipher.counter);
                    expect(deserialized.nonce).to.exist;
                    expect(deserialized.nonce?.toBase64URL()).equals(cipher.nonce?.toBase64URL());
                    expect(deserialized.algorithm).equals(cipher.algorithm);
                });

                it("should decrypt to the same message", async function () {
                    const cipher = await CryptoEncryption.encrypt(text, key);
                    const plaintext = await CryptoEncryption.decrypt(cipher, key);
                    expect(plaintext.toArray()).to.have.members(text.toArray());
                });

                it("should deserialize/serialize a CryptoCipher with nonce", function () {
                    const nonce = CoreBuffer.random(24);
                    const cipher = CryptoCipher.from({
                        algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        cipher: nonce,
                        nonce: nonce
                    });
                    expect(cipher.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                    expect(cipher.cipher.toBase64URL()).to.equal(nonce.toBase64URL());
                    expect(cipher.nonce).to.exist;
                    expect(cipher.nonce?.toBase64URL()).to.equal(nonce.toBase64URL());
                    expect(cipher.counter).to.not.exist;
                });

                it("should deserialize/serialize a CryptoCipher with counter", function () {
                    const nonce = CoreBuffer.random(24);
                    const cipher = CryptoCipher.fromJSON({
                        alg: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        cph: nonce.toBase64URL(),
                        cnt: 0
                    });
                    expect(cipher.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                    expect(cipher.cipher.toBase64URL()).to.equal(nonce.toBase64URL());
                    expect(cipher.counter).to.equal(0);
                    expect(cipher.nonce).to.not.exist;
                });

                it("should decrypt to the same message with given nonce", async function () {
                    const nonce = CoreBuffer.random(24);
                    const cipher = await CryptoEncryption.encrypt(text, key, nonce);
                    const plaintext = await CryptoEncryption.decrypt(cipher, key);
                    expect(plaintext.toArray()).to.have.members(text.toArray());
                });

                it("should decrypt to the same message with given nonce and counter", async function () {
                    const nonce = CoreBuffer.random(24);
                    let cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 0);
                    let plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 0);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 1);
                    plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 1);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 4000);
                    plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 4000);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 400000);
                    plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 400000);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 9999999);
                    plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 9999999);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 999999999);
                    plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 999999999);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 4290000000);
                    plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 4290000000);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 4294967295);
                    plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 4294967295);
                    expect(plaintext.toArray()).to.have.members(text.toArray());
                });

                it("should throw an error on wrong counters", async function () {
                    const nonce = CoreBuffer.random(24);
                    const cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 0);
                    let error;
                    try {
                        await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 1);
                    } catch (e: any) {
                        error = e;
                    }

                    expect(error).to.be.instanceOf(CryptoError);
                    expect(error.code).to.equal("error.crypto.encryption.decrypt");
                });

                it("should throw an error on wrong key", async function () {
                    const nonce = CoreBuffer.random(24);
                    const wrongkey = await CryptoEncryption.generateKey();
                    const cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 0);
                    let error;
                    try {
                        await CryptoEncryption.decryptWithCounter(cipher, wrongkey, nonce, 0);
                    } catch (e: any) {
                        error = e;
                    }

                    expect(error).to.be.instanceOf(CryptoError);
                    expect(error.code).to.equal("error.crypto.encryption.decrypt");
                });

                it("should create a different CryptoCipher every time", async function () {
                    const cipher1 = await CryptoEncryption.encrypt(text, key2);
                    const cipher2 = await CryptoEncryption.encrypt(text, key2);
                    const cipher3 = await CryptoEncryption.encrypt(text, key2);

                    expect(cipher1.cipher.toArray()).not.to.have.members(cipher2.cipher.toArray());
                    expect(cipher2.cipher.toArray()).not.to.have.members(cipher3.cipher.toArray());

                    const plaintext1 = await CryptoEncryption.decrypt(cipher1, key2);
                    const plaintext2 = await CryptoEncryption.decrypt(cipher2, key2);
                    const plaintext3 = await CryptoEncryption.decrypt(cipher3, key2);

                    expect(plaintext1.toArray()).to.have.members(text.toArray());
                    expect(plaintext2.toArray()).to.have.members(text.toArray());
                    expect(plaintext3.toArray()).to.have.members(text.toArray());
                });
            });
        });
    }
}
