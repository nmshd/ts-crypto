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
    CryptoSecretKeyHandle,
    ICryptoSecretKeySerialized
} from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../../index";
import { parameterizedKeySpec } from "../CryptoLayerTestUtil";
import { assertSecretKeyHandleEqual, assertSecretKeyHandleValid } from "../KeyValidation";

export class CryptoEncryptionHandleTest {
    public static run(): void {
        describe("CryptoEncryptionHandle", function () {
            describe("Key Creation and Usage", function () {
                parameterizedKeySpec("should generate secret key handle with", async function (spec: KeySpec) {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                    await assertSecretKeyHandleValid(cryptoSecretKeyHandle);
                });

                parameterizedKeySpec(
                    "from ICryptoSecretKeyHandle should load a crypto secret key handle",
                    async function (spec: KeySpec) {
                        const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(
                            TEST_PROVIDER_IDENT,
                            spec
                        );
                        await assertSecretKeyHandleValid(cryptoSecretKeyHandle);

                        const loadedSecretKeyHandle = await CryptoSecretKeyHandle.from({
                            id: cryptoSecretKeyHandle.id,
                            spec: cryptoSecretKeyHandle.spec,
                            providerName: cryptoSecretKeyHandle.providerName
                        });
                        await assertSecretKeyHandleValid(loadedSecretKeyHandle);

                        await assertSecretKeyHandleEqual(cryptoSecretKeyHandle, loadedSecretKeyHandle);
                    },
                    {
                        ephemeral: [false]
                    }
                );

                parameterizedKeySpec(
                    "from CryptoSecretKeyHandle should load a crypto secret key handle",
                    async function (spec: KeySpec) {
                        const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(
                            TEST_PROVIDER_IDENT,
                            spec
                        );
                        await assertSecretKeyHandleValid(cryptoSecretKeyHandle);

                        const loadedSecretKeyHandle = await CryptoSecretKeyHandle.from(cryptoSecretKeyHandle);
                        await assertSecretKeyHandleValid(loadedSecretKeyHandle);

                        await assertSecretKeyHandleEqual(cryptoSecretKeyHandle, loadedSecretKeyHandle);
                    },
                    {
                        ephemeral: [false]
                    }
                );

                parameterizedKeySpec("decrypt encrypt should be an identity function", async function (spec: KeySpec) {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                    const data = new CoreBuffer("0123456789ABCDEF");
                    const encrypted = await CryptoEncryptionHandle.encrypt(data, cryptoSecretKeyHandle);
                    expect(encrypted).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                    expect(encrypted.algorithm).to.equal(
                        CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(cryptoSecretKeyHandle.spec.cipher)
                    );

                    const decrypted = await CryptoEncryptionHandle.decrypt(encrypted, cryptoSecretKeyHandle);

                    expect(decrypted.buffer).to.deep.equal(data.buffer);
                });

                parameterizedKeySpec(
                    "decrypt encrypt with counter should be an identity function",
                    async function (spec: KeySpec) {
                        const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(
                            TEST_PROVIDER_IDENT,
                            spec
                        );
                        const cryptoEncryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(
                            cryptoSecretKeyHandle.spec.cipher
                        );

                        const nonce = await CryptoEncryptionHandle.createNonce(
                            cryptoEncryptionAlgorithm,
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
                        expect(encrypted.algorithm).to.equal(cryptoEncryptionAlgorithm);

                        const decrypted = await CryptoEncryptionHandle.decryptWithCounter(
                            encrypted,
                            cryptoSecretKeyHandle,
                            nonce,
                            222
                        );

                        expect(decrypted.buffer).to.deep.equal(data.buffer);
                    }
                );

                parameterizedKeySpec(
                    "decrypt encrypt with provided nonce should be an identity function",
                    async function (spec: KeySpec) {
                        const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(
                            TEST_PROVIDER_IDENT,
                            spec
                        );
                        const cryptoEncryptionAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(
                            cryptoSecretKeyHandle.spec.cipher
                        );

                        const nonce = await CryptoEncryptionHandle.createNonce(
                            cryptoEncryptionAlgorithm,
                            cryptoSecretKeyHandle.provider
                        );

                        const data = new CoreBuffer("0123456789ABCDEF");
                        const encrypted = await CryptoEncryptionHandle.encrypt(data, cryptoSecretKeyHandle, nonce);
                        expect(encrypted).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                        expect(encrypted.algorithm).to.equal(cryptoEncryptionAlgorithm);

                        const decrypted = await CryptoEncryptionHandle.decrypt(encrypted, cryptoSecretKeyHandle, nonce);

                        expect(decrypted.buffer).to.deep.equal(data.buffer);
                    }
                );

                parameterizedKeySpec("encrypt with a wrong nonce should fail", async function (spec: KeySpec) {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                    const nonce = new CoreBuffer("ZnZj");

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

            describe("Validation against CryptoSecretKey", function () {
                const spec: KeySpec = {
                    cipher: "XChaCha20Poly1305",
                    signing_hash: "Sha2_256",
                    ephemeral: false
                };

                it("extracted key imported in libsodium should be able to decrypt", async function () {
                    const key = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                    const rawKey = await key.keyHandle.extractKey();
                    const keyBuffer = new CoreBuffer(rawKey);
                    const algorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(key.spec.cipher);
                    const keyObject: ICryptoSecretKeySerialized = {
                        alg: algorithm,
                        key: keyBuffer.toBase64URL()
                    };

                    const libsodiumKey = CryptoSecretKey.fromJSON(keyObject);

                    const payload = CoreBuffer.random(4);
                    const ciphertext = await CryptoEncryptionHandle.encrypt(payload, key);
                    expect(ciphertext).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                    expect(ciphertext.algorithm).to.equal(algorithm);

                    const decrypted = await CryptoEncryption.decrypt(ciphertext, libsodiumKey);

                    expect(decrypted.buffer).to.deep.equal(payload.buffer);
                });

                it("libsodium key should be importable", async function () {
                    const libsodiumKey = await CryptoEncryption.generateKey(
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
                    );

                    const spec: KeySpec = {
                        cipher: CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(libsodiumKey.algorithm),
                        signing_hash: "Sha2_256",
                        ephemeral: false
                    };

                    const keyHandle = await CryptoSecretKeyHandle.fromRawKey(
                        TEST_PROVIDER_IDENT,
                        libsodiumKey.secretKey,
                        spec
                    );
                    await assertSecretKeyHandleValid(keyHandle);

                    expect(await keyHandle.keyHandle.extractKey()).to.deep.equal(libsodiumKey.secretKey.buffer);
                });
            });

            describe("Legacy Tests with XCHACHA20_POLY1305", function () {
                const spec: KeySpec = {
                    cipher: "XChaCha20Poly1305",
                    signing_hash: "Sha2_256",
                    ephemeral: false
                };

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
            });

            describe("Execute encrypt() with XCHACHA20_POLY1305", function () {
                let key: CryptoSecretKeyHandle;
                let key2: CryptoSecretKeyHandle;
                const text: CoreBuffer = CoreBuffer.random(4);
                const spec: KeySpec = {
                    cipher: "XChaCha20Poly1305",
                    signing_hash: "Sha2_256",
                    ephemeral: false
                };
                const expectedAlgorithm = CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(spec.cipher);

                before(async function () {
                    key = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                    key2 = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                });

                it("should return a CryptoCipher with random nonce", async function () {
                    const cipher = await CryptoEncryptionHandle.encrypt(text, key);
                    expect(cipher).to.exist;
                    expect(cipher).to.be.instanceOf(CryptoCipher);
                    expect(cipher.algorithm).to.be.equal(expectedAlgorithm);
                    expect(cipher.counter).to.not.exist;
                    expect(cipher.nonce).to.exist;
                    expect(cipher.nonce?.buffer.byteLength).to.equal(24);
                });

                it("should serialize and deserialize the cipher", async function () {
                    const cipher = await CryptoEncryptionHandle.encrypt(text, key);

                    const a = CryptoCipher.deserialize(cipher.serialize());
                    expect(a.cipher.toBase64()).equals(cipher.cipher.toBase64());

                    const b = CryptoCipher.fromJSON(cipher.toJSON());
                    expect(b.cipher.toBase64()).equals(cipher.cipher.toBase64());
                });

                it("should serialize and deserialize the cipher from @type", async function () {
                    const cipher = await CryptoEncryptionHandle.encrypt(text, key);

                    const serialized = cipher.serialize();
                    const deserialized = (await SerializableAsync.deserializeUnknown(serialized)) as CryptoCipher;
                    expect(deserialized).instanceOf(CryptoCipher);
                    expect(deserialized.cipher.toBase64URL()).equals(cipher.cipher.toBase64URL());
                    expect(deserialized.counter).equals(cipher.counter);
                    expect(deserialized.nonce).to.exist;
                    expect(deserialized.nonce?.toBase64URL()).equals(cipher.nonce?.toBase64URL());
                    expect(deserialized.algorithm).equals(cipher.algorithm);
                });

                it("should decrypt to the same message", async function () {
                    const cipher = await CryptoEncryptionHandle.encrypt(text, key);
                    const plaintext = await CryptoEncryptionHandle.decrypt(cipher, key);
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
                    const cipher = await CryptoEncryptionHandle.encrypt(text, key, nonce);
                    const plaintext = await CryptoEncryptionHandle.decrypt(cipher, key);
                    expect(plaintext.toArray()).to.have.members(text.toArray());
                });

                it("should decrypt to the same message with given nonce and counter", async function () {
                    const nonce = CoreBuffer.random(24);
                    let cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 0);
                    let plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 0);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 1);
                    plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 1);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 4000);
                    plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 4000);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 400000);
                    plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 400000);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 9999999);
                    plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 9999999);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 999999999);
                    plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 999999999);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 4290000000);
                    plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 4290000000);
                    expect(plaintext.toArray()).to.have.members(text.toArray());

                    cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 4294967295);
                    plaintext = await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 4294967295);
                    expect(plaintext.toArray()).to.have.members(text.toArray());
                });

                it("should throw an error on wrong counters", async function () {
                    const nonce = CoreBuffer.random(24);
                    const cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 0);
                    let error;
                    try {
                        await CryptoEncryptionHandle.decryptWithCounter(cipher, key, nonce, 1);
                    } catch (e: any) {
                        error = e;
                    }

                    expect(error).to.be.instanceOf(CryptoError);
                    expect(error.code).to.equal("error.crypto.encryption.decrypt");
                });

                it("should throw an error on wrong key", async function () {
                    const nonce = CoreBuffer.random(24);
                    const cipher = await CryptoEncryptionHandle.encryptWithCounter(text, key, nonce, 0);
                    let error;
                    try {
                        await CryptoEncryptionHandle.decryptWithCounter(cipher, key2, nonce, 0);
                    } catch (e: any) {
                        error = e;
                    }

                    expect(error).to.be.instanceOf(CryptoError);
                    expect(error.code).to.equal("error.crypto.encryption.decrypt");
                });

                it("should create a different CryptoCipher every time", async function () {
                    const cipher1 = await CryptoEncryptionHandle.encrypt(text, key);
                    const cipher2 = await CryptoEncryptionHandle.encrypt(text, key);
                    expect(cipher1.cipher.toBase64URL()).to.not.equal(cipher2.cipher.toBase64URL());
                    if (cipher1.nonce && cipher2.nonce) {
                        expect(cipher1.nonce.toBase64URL()).to.not.equal(cipher2.nonce.toBase64URL());
                    }
                });
            });
        });
    }
}
