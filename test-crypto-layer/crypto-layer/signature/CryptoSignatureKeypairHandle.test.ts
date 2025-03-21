/* eslint-disable @typescript-eslint/naming-convention */
import {
    CoreBuffer,
    CryptoHashAlgorithm,
    CryptoSignature,
    CryptoSignatureKeypairHandle,
    CryptoSignatures
} from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { TestSerializeDeserializeOfCryptoKeyPairHandle } from "../CommonSerialize";
import { parameterizedKeyPairSpec } from "../CryptoLayerTestUtil";
import { assertCryptoKeyPairHandleValid } from "../KeyValidation";

export class CryptoSignatureKeypairHandleTest {
    public static run(): void {
        describe("CryptoSignatureKeypairHandle", function () {
            describe("generateKeyPairHandle() SoftwareProvider", function () {
                const spec: KeyPairSpec = {
                    asym_spec: "P256",
                    cipher: null,
                    signing_hash: "Sha2_512",
                    ephemeral: false,
                    non_exportable: false
                };
                const providerIdent = { providerName: "SoftwareProvider" };

                parameterizedKeyPairSpec("generateKeyPairHandle()", async function (spec: KeyPairSpec) {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(
                        { providerName: "SoftwareProvider" },
                        spec
                    );
                    await assertCryptoKeyPairHandleValid(cryptoKeyPairHandle);
                });

                it("from() ICryptoSignatureKeypairHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    await assertCryptoKeyPairHandleValid(cryptoKeyPairHandle);

                    const loadedKeyPairHandle = await CryptoSignatureKeypairHandle.fromAny({
                        publicKey: {
                            id: cryptoKeyPairHandle.publicKey.id,
                            spec: cryptoKeyPairHandle.publicKey.spec,
                            providerName: cryptoKeyPairHandle.publicKey.providerName
                        },
                        privateKey: {
                            id: cryptoKeyPairHandle.publicKey.id,
                            spec: cryptoKeyPairHandle.publicKey.spec,
                            providerName: cryptoKeyPairHandle.publicKey.providerName
                        }
                    });
                    await assertCryptoKeyPairHandleValid(loadedKeyPairHandle);

                    expect(loadedKeyPairHandle.privateKey.id).to.equal(cryptoKeyPairHandle.privateKey.id);
                    expect(loadedKeyPairHandle.publicKey.id).to.equal(cryptoKeyPairHandle.publicKey.id);
                });

                it("from() ICryptoSignatureKeypairHandle 2", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(
                        { providerName: "SoftwareProvider" },
                        spec
                    );
                    await assertCryptoKeyPairHandleValid(cryptoKeyPairHandle);

                    const loadedKeyPairHandle = await CryptoSignatureKeypairHandle.fromAny({
                        publicKey: cryptoKeyPairHandle.publicKey,
                        privateKey: cryptoKeyPairHandle.privateKey
                    });
                    await assertCryptoKeyPairHandleValid(loadedKeyPairHandle);

                    expect(loadedKeyPairHandle.privateKey.id).to.equal(cryptoKeyPairHandle.privateKey.id);
                    expect(loadedKeyPairHandle.publicKey.id).to.equal(cryptoKeyPairHandle.publicKey.id);
                });

                it("from() CryptoSignatureKeypairHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    await assertCryptoKeyPairHandleValid(cryptoKeyPairHandle);

                    const loadedKeyPairHandle = await CryptoSignatureKeypairHandle.from(cryptoKeyPairHandle);
                    await assertCryptoKeyPairHandleValid(loadedKeyPairHandle);

                    expect(loadedKeyPairHandle.privateKey.id).to.equal(cryptoKeyPairHandle.privateKey.id);
                    expect(loadedKeyPairHandle.publicKey.id).to.equal(cryptoKeyPairHandle.publicKey.id);
                });

                TestSerializeDeserializeOfCryptoKeyPairHandle(
                    "CryptoSignatureKeypairHandle",
                    async () => await CryptoSignatures.generateKeypairHandle(providerIdent, spec),
                    CryptoSignatureKeypairHandle
                );

                it("sign() and verify()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);

                    const data = new CoreBuffer("0123456789ABCDEF");
                    const signature = await CryptoSignatures.sign(
                        data,
                        cryptoKeyPairHandle.privateKey,
                        CryptoHashAlgorithm.SHA512,
                        undefined,
                        "1234"
                    );
                    expect(signature).to.be.ok.and.to.be.instanceOf(CryptoSignature);
                    expect(signature.keyId).to.be.ok.and.to.equal(cryptoKeyPairHandle.privateKey.id);
                    expect(signature.id).to.equal("1234");
                    expect(signature.algorithm).to.equal(CryptoHashAlgorithm.SHA512);

                    expect(await CryptoSignatures.verify(data, signature, cryptoKeyPairHandle.publicKey)).to.equal(
                        true
                    );
                });
            });
        });
    }
}
