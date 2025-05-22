/* eslint-disable @typescript-eslint/naming-convention */
import { SerializableAsync } from "@js-soft/ts-serval";
import {
    CoreBuffer,
    CryptoCipher,
    CryptoEncryption,
    CryptoEncryptionAlgorithm,
    CryptoEncryptionHandle,
    CryptoError,
    CryptoLayerUtils,
    CryptoSecretKey,
    CryptoSecretKeyHandle
} from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../../index";
import { parameterizedKeySpec } from "../CryptoLayerTestUtil";
import { assertSecretKeyHandleValid } from "../KeyValidation";

export class CryptoSecretKeyHandleTest {
    public static run(): void {
        describe("CryptoEncryption", function () {
            const spec: KeySpec = {
                cipher: "XChaCha20Poly1305",
                signing_hash: "Sha2_256",
                ephemeral: false
            };
            describe("generateSecretKeyHandle() SoftwareProvider", function () {
                parameterizedKeySpec("generateSecretKeyHandle()", async function (spec: KeySpec) {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                    await assertSecretKeyHandleValid(cryptoSecretKeyHandle);
                });

                it("from() ICryptoSecretKeyHandle", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                    await assertSecretKeyHandleValid(cryptoSecretKeyHandle);

                    const loadedSecretKeyHandle = await CryptoSecretKeyHandle.fromAny({
                        id: cryptoSecretKeyHandle.id,
                        spec: cryptoSecretKeyHandle.spec,
                        providerName: cryptoSecretKeyHandle.providerName
                    });
                    await assertSecretKeyHandleValid(loadedSecretKeyHandle);

                    expect(loadedSecretKeyHandle.id).to.equal(cryptoSecretKeyHandle.id);
                });

                it("from() CryptoSecretKeyHandle", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                    await assertSecretKeyHandleValid(cryptoSecretKeyHandle);

                    const loadedSecretKeyHandle = await CryptoSecretKeyHandle.from(cryptoSecretKeyHandle);
                    await assertSecretKeyHandleValid(loadedSecretKeyHandle);

                    expect(loadedSecretKeyHandle.id).to.equal(cryptoSecretKeyHandle.id);
                });

                it("encrypt() and decrypt()", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                    const data = new CoreBuffer("0123456789ABCDEF");
                    const encrypted = await CryptoEncryptionHandle.encrypt(data, cryptoSecretKeyHandle);
                    expect(encrypted).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                    expect(encrypted.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);

                    const decrypted = await CryptoEncryptionHandle.decrypt(encrypted, cryptoSecretKeyHandle);

                    expect(decrypted.buffer).to.deep.equal(data.buffer);
                });

                it("encrypt() and decrypt() with counter", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                    const nonce = await CryptoEncryptionHandle.createNonce(
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        cryptoSecretKeyHandle.provider
                    );

                    const data = new CoreBuffer("0123456789ABCDEF");
                    const encrypted = await CryptoEncryptionHandle.encryptWithCounter(
                        data,
                        cryptoSecretKeyHandle,
                        nonce,
                        222
                    );
                    expect(encrypted).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                    expect(encrypted.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);

                    const decrypted = await CryptoEncryptionHandle.decryptWithCounter(
                        encrypted,
                        cryptoSecretKeyHandle,
                        nonce,
                        222
                    );

                    expect(decrypted.buffer).to.deep.equal(data.buffer);
                });

                it("encrypt() and decrypt() with provided nonce", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                    const nonce = await CryptoEncryptionHandle.createNonce(
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        cryptoSecretKeyHandle.provider
                    );

                    console.log(`provided nonce length = ${nonce.buffer.length}`);

                    const data = new CoreBuffer("0123456789ABCDEF");
                    const encrypted = await CryptoEncryptionHandle.encrypt(data, cryptoSecretKeyHandle, nonce);
                    expect(encrypted).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                    expect(encrypted.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);

                    const decrypted = await CryptoEncryptionHandle.decrypt(encrypted, cryptoSecretKeyHandle, nonce);

                    expect(decrypted.buffer).to.deep.equal(data.buffer);
                });

                it("encrypt() with wrong nonce fails", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                    const nonce = new CoreBuffer("ZnZj");

                    console.log(`provided nonce length = ${nonce.buffer.length}`);

                    const data = new CoreBuffer("0123456789ABCDEF");

                    let error;
                    try {
                        await CryptoEncryptionHandle.encrypt(data, cryptoSecretKeyHandle, nonce);
                    } catch (e: any) {
                        error = e;
                    }

                    expect(error).to.be.instanceOf(CryptoError);
                    expect(error.code).to.equal("error.crypto.encryption.wrongNonce");
                });
            });

            describe("Execute generateKey() with XCHACHA20_POLY1305", function () {
                let key: CryptoSecretKeyHandle;
                before(async function () {
                    key = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                });

                it("should return a SecretKey", function () {
                    expect(key).to.exist;
                    expect(key).to.be.instanceOf(CryptoSecretKeyHandle);
                    expect(key.spec).to.exist;
                    expect(key.keyHandle).to.exist;
                });

                it("should return a correct algorithm in the key", function () {
                    expect(key.spec).to.be.equal(spec);
                });

                it("should serialize and deserialize the key correctly", async function () {
                    const serialized = key.serialize();
                    const deserialized = await CryptoSecretKeyHandle.deserialize(serialized);
                    expect(deserialized.keyHandle).to.deep.equal(key.keyHandle);
                    expect(deserialized.id).to.equal(key.id);
                    expect(deserialized.spec).to.deep.equal(key.spec);
                });

                it("should serialize and deserialize the key using base64 correctly", async function () {
                    const serialized = key.toBase64();
                    const deserialized = await CryptoSecretKeyHandle.fromBase64(serialized);
                    expect(deserialized.keyHandle).to.deep.equal(key.keyHandle);
                    expect(deserialized.id).to.equal(key.id);
                    expect(deserialized.spec).to.deep.equal(key.spec);
                });

                it("should serialize and deserialize the key correctly from @type", async function () {
                    const serialized = key.serialize();
                    const deserialized = (await SerializableAsync.deserializeUnknown(
                        serialized
                    )) as CryptoSecretKeyHandle;
                    expect(deserialized).instanceOf(CryptoSecretKeyHandle);
                    expect(deserialized.keyHandle).to.deep.equal(key.keyHandle);
                    expect(deserialized.id).to.equal(key.id);
                    expect(deserialized.spec).to.deep.equal(key.spec);
                });

                it("extracted key imported in libsodium should be able to decrypt.", async function () {
                    const rawKey = await key.keyHandle.extractKey();
                    const keyBuffer = new CoreBuffer(rawKey);
                    const algorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(key.spec.cipher);
                    const keyObject = {
                        alg: algorithm,
                        key: keyBuffer.toBase64URL()
                    };

                    const libsodiumKey = CryptoSecretKey.fromJSON(keyObject);

                    const data = CoreBuffer.random(4);
                    const encrypted = await CryptoEncryptionHandle.encrypt(data, key);
                    const encryptedLibsodium = await CryptoEncryption.encrypt(data, libsodiumKey);
                    console.log(encrypted);
                    console.log(encryptedLibsodium);
                    expect(encrypted).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                    expect(encrypted.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);

                    const decrypted = await CryptoEncryption.decrypt(encrypted, libsodiumKey);

                    expect(decrypted.buffer).to.deep.equal(data.buffer);
                });
            });

            // describe("Execute encrypt() with XCHACHA20_POLY1305", function () {
            //     let key: CryptoSecretKeyHandle;
            //     let key2: CryptoSecretKeyHandle;
            //     const text: CoreBuffer = CoreBuffer.random(4);
            //     before(async function () {
            //         key = await CryptoEncryption.generateKey(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
            //         key2 = await CryptoEncryption.generateKey(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
            //     });

            //     it("should return a CryptoCipher with random nonce", async function () {
            //         const cipher = await CryptoEncryption.encrypt(text, key);
            //         expect(cipher).to.exist;
            //         expect(cipher).to.be.instanceOf(CryptoCipher);
            //         expect(cipher.algorithm).to.be.equal(key.algorithm);
            //         expect(cipher.counter).to.not.exist;
            //         expect(cipher.nonce).to.exist;
            //         expect(cipher.nonce?.buffer.byteLength).to.equal(24);
            //     });

            //     it("should serialize and deserialize the cipher", async function () {
            //         const cipher = await CryptoEncryption.encrypt(text, key);

            //         const a = CryptoCipher.deserialize(cipher.serialize());
            //         expect(a.cipher.toBase64()).equals(cipher.cipher.toBase64());

            //         const b = CryptoCipher.fromJSON(cipher.toJSON());
            //         expect(b.cipher.toBase64()).equals(cipher.cipher.toBase64());
            //     });

            //     it("should serialize and deserialize the cipher from @type", async function () {
            //         const cipher = await CryptoEncryption.encrypt(text, key);

            //         const serialized = cipher.serialize();
            //         const deserialized = Serializable.deserializeUnknown(serialized) as CryptoCipher;
            //         expect(deserialized).instanceOf(CryptoCipher);
            //         expect(deserialized.cipher.toBase64URL()).equals(cipher.cipher.toBase64URL());
            //         expect(deserialized.counter).equals(cipher.counter);
            //         expect(deserialized.nonce).to.exist;
            //         expect(deserialized.nonce?.toBase64URL()).equals(cipher.nonce?.toBase64URL());
            //         expect(deserialized.algorithm).equals(cipher.algorithm);
            //     });

            //     it("should decrypt to the same message", async function () {
            //         const cipher = await CryptoEncryption.encrypt(text, key);
            //         const plaintext = await CryptoEncryption.decrypt(cipher, key);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());
            //     });

            //     it("should deserialize/serialize a CryptoCipher with nonce", function () {
            //         const nonce = CoreBuffer.random(24);
            //         const cipher = CryptoCipher.from({
            //             algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            //             cipher: nonce,
            //             nonce: nonce
            //         });
            //         expect(cipher.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
            //         expect(cipher.cipher.toBase64URL()).to.equal(nonce.toBase64URL());
            //         expect(cipher.nonce).to.exist;
            //         expect(cipher.nonce?.toBase64URL()).to.equal(nonce.toBase64URL());
            //         expect(cipher.counter).to.not.exist;
            //     });

            //     it("should deserialize/serialize a CryptoCipher with counter", function () {
            //         const nonce = CoreBuffer.random(24);
            //         const cipher = CryptoCipher.fromJSON({
            //             alg: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            //             cph: nonce.toBase64URL(),
            //             cnt: 0
            //         });
            //         expect(cipher.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
            //         expect(cipher.cipher.toBase64URL()).to.equal(nonce.toBase64URL());
            //         expect(cipher.counter).to.equal(0);
            //         expect(cipher.nonce).to.not.exist;
            //     });

            //     it("should decrypt to the same message with given nonce", async function () {
            //         const nonce = CoreBuffer.random(24);
            //         const cipher = await CryptoEncryption.encrypt(text, key, nonce);
            //         const plaintext = await CryptoEncryption.decrypt(cipher, key);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());
            //     });

            //     it("should decrypt to the same message with given nonce and counter", async function () {
            //         const nonce = CoreBuffer.random(24);
            //         let cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 0);
            //         let plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 0);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());

            //         cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 1);
            //         plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 1);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());

            //         cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 4000);
            //         plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 4000);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());

            //         cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 400000);
            //         plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 400000);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());

            //         cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 9999999);
            //         plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 9999999);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());

            //         cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 999999999);
            //         plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 999999999);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());

            //         cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 4290000000);
            //         plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 4290000000);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());

            //         cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 4294967295);
            //         plaintext = await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 4294967295);
            //         expect(plaintext.toArray()).to.have.members(text.toArray());
            //     });

            //     it("should throw an error on wrong counters", async function () {
            //         const nonce = CoreBuffer.random(24);
            //         const cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 0);
            //         let error;
            //         try {
            //             await CryptoEncryption.decryptWithCounter(cipher, key, nonce, 1);
            //         } catch (e: any) {
            //             error = e;
            //         }

            //         expect(error).to.be.instanceOf(CryptoError);
            //         expect(error.code).to.equal("error.crypto.encryption.decrypt");
            //     });

            //     it("should throw an error on wrong key", async function () {
            //         const nonce = CoreBuffer.random(24);
            //         const wrongkey = await CryptoEncryption.generateKey();
            //         const cipher = await CryptoEncryption.encryptWithCounter(text, key, nonce, 0);
            //         let error;
            //         try {
            //             await CryptoEncryption.decryptWithCounter(cipher, wrongkey, nonce, 0);
            //         } catch (e: any) {
            //             error = e;
            //         }

            //         expect(error).to.be.instanceOf(CryptoError);
            //         expect(error.code).to.equal("error.crypto.encryption.decrypt");
            //     });

            //     it("should create a different CryptoCipher every time", async function () {
            //         const cipher1 = await CryptoEncryption.encrypt(text, key2);
            //         const cipher2 = await CryptoEncryption.encrypt(text, key2);
            //         const cipher3 = await CryptoEncryption.encrypt(text, key2);

            //         expect(cipher1.cipher.toArray()).not.to.have.members(cipher2.cipher.toArray());
            //         expect(cipher2.cipher.toArray()).not.to.have.members(cipher3.cipher.toArray());

            //         const plaintext1 = await CryptoEncryption.decrypt(cipher1, key2);
            //         const plaintext2 = await CryptoEncryption.decrypt(cipher2, key2);
            //         const plaintext3 = await CryptoEncryption.decrypt(cipher3, key2);

            //         expect(plaintext1.toArray()).to.have.members(text.toArray());
            //         expect(plaintext2.toArray()).to.have.members(text.toArray());
            //         expect(plaintext3.toArray()).to.have.members(text.toArray());
            //     });
            // });
        });
    }
}
