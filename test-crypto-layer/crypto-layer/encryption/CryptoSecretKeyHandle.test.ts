/* eslint-disable @typescript-eslint/naming-convention */
import {
    CoreBuffer,
    CryptoCipher,
    CryptoEncryptionAlgorithm,
    CryptoEncryptionHandle,
    CryptoSecretKeyHandle
} from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { parameterizedKeySpec } from "../CryptoLayerTestUtil";
import { assertSecretKeyHandleValid } from "../KeyValidation";

export class CryptoSecretKeyHandleTest {
    public static run(): void {
        describe("CryptoSecretKeyHandle", function () {
            describe("generateSecretKeyHandle() SoftwareProvider", function () {
                const spec: KeySpec = {
                    cipher: "AesGcm256",
                    signing_hash: "Sha2_256",
                    ephemeral: false
                };
                const providerIdent = { providerName: "SoftwareProvider" };

                parameterizedKeySpec("generateSecretKeyHandle()", async function (spec: KeySpec) {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(providerIdent, spec);
                    await assertSecretKeyHandleValid(cryptoSecretKeyHandle);
                });

                it("from() ICryptoSecretKeyHandle", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(providerIdent, spec);
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
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(providerIdent, spec);
                    await assertSecretKeyHandleValid(cryptoSecretKeyHandle);

                    const loadedSecretKeyHandle = await CryptoSecretKeyHandle.from(cryptoSecretKeyHandle);
                    await assertSecretKeyHandleValid(loadedSecretKeyHandle);

                    expect(loadedSecretKeyHandle.id).to.equal(cryptoSecretKeyHandle.id);
                });

                it("encrypt() and decrypt()", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(providerIdent, spec);

                    const data = new CoreBuffer("0123456789ABCDEF");
                    const encrypted = await CryptoEncryptionHandle.encrypt(data, cryptoSecretKeyHandle);
                    expect(encrypted).to.be.ok.and.to.be.instanceOf(CryptoCipher);
                    expect(encrypted.algorithm).to.equal(CryptoEncryptionAlgorithm.AES256_GCM);

                    const decrypted = await CryptoEncryptionHandle.decrypt(encrypted, cryptoSecretKeyHandle);

                    expect(decrypted.buffer).to.deep.equal(data.buffer);
                });

                it("encrypt() and decrypt() with counter", async function () {
                    const cryptoSecretKeyHandle = await CryptoEncryptionHandle.generateKey(providerIdent, spec);

                    const nonce = await CryptoEncryptionHandle.createNonce(
                        CryptoEncryptionAlgorithm.AES256_GCM,
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
                    expect(encrypted.algorithm).to.equal(CryptoEncryptionAlgorithm.AES256_GCM);

                    const decrypted = await CryptoEncryptionHandle.decryptWithCounter(
                        encrypted,
                        cryptoSecretKeyHandle,
                        nonce,
                        222
                    );

                    expect(decrypted.buffer).to.deep.equal(data.buffer);
                });
            });
        });
    }
}
