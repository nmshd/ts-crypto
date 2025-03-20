/* eslint-disable @typescript-eslint/naming-convention */
import {
    CoreBuffer,
    CryptoHashAlgorithm,
    CryptoSignature,
    CryptoSignatureKeypairHandle,
    CryptoSignaturePrivateKeyHandle,
    CryptoSignaturePublicKeyHandle,
    CryptoSignatures
} from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { assertCryptoAsymmetricKeyHandle } from "../CryptoAsymmetricKeyHandle";
import { parameterizedKeyPairSpec } from "../CryptoLayerTestUtil";

export async function expectCryptoSignatureKeypairHandle(
    cryptoKeyPairHandle: CryptoSignatureKeypairHandle,
    expectedProvider: string,
    spec: KeyPairSpec
): Promise<void> {
    expect(cryptoKeyPairHandle).to.be.instanceOf(CryptoSignatureKeypairHandle);
    expect(cryptoKeyPairHandle.privateKey).to.be.instanceOf(CryptoSignaturePrivateKeyHandle);
    expect(cryptoKeyPairHandle.publicKey).to.be.instanceOf(CryptoSignaturePublicKeyHandle);

    assertCryptoAsymmetricKeyHandle(cryptoKeyPairHandle.privateKey);
    assertCryptoAsymmetricKeyHandle(cryptoKeyPairHandle.publicKey);

    expect(cryptoKeyPairHandle.privateKey.keyPairHandle).to.be.ok.and.deep.equal(
        cryptoKeyPairHandle.publicKey.keyPairHandle
    );
}

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
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);
                });

                it("from() ICryptoSignatureKeypairHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);

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
                    await expectCryptoSignatureKeypairHandle(loadedKeyPairHandle, "SoftwareProvider", spec);

                    expect(loadedKeyPairHandle.privateKey.id).to.equal(cryptoKeyPairHandle.privateKey.id);
                    expect(loadedKeyPairHandle.publicKey.id).to.equal(cryptoKeyPairHandle.publicKey.id);
                });

                it("from() ICryptoSignatureKeypairHandle 2", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(
                        { providerName: "SoftwareProvider" },
                        spec
                    );
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);

                    const loadedKeyPairHandle = await CryptoSignatureKeypairHandle.fromAny({
                        publicKey: cryptoKeyPairHandle.publicKey,
                        privateKey: cryptoKeyPairHandle.privateKey
                    });
                    await expectCryptoSignatureKeypairHandle(loadedKeyPairHandle, "SoftwareProvider", spec);

                    expect(loadedKeyPairHandle.privateKey.id).to.equal(cryptoKeyPairHandle.privateKey.id);
                    expect(loadedKeyPairHandle.publicKey.id).to.equal(cryptoKeyPairHandle.publicKey.id);
                });

                it("from() CryptoSignatureKeypairHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);

                    const loadedKeyPairHandle = await CryptoSignatureKeypairHandle.from(cryptoKeyPairHandle);
                    await expectCryptoSignatureKeypairHandle(loadedKeyPairHandle, "SoftwareProvider", spec);

                    expect(loadedKeyPairHandle.privateKey.id).to.equal(cryptoKeyPairHandle.privateKey.id);
                    expect(loadedKeyPairHandle.publicKey.id).to.equal(cryptoKeyPairHandle.publicKey.id);
                });

                it("toJSON() and fromJSON()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);

                    const jsonKeyPairHandle = cryptoKeyPairHandle.toJSON();
                    expect(jsonKeyPairHandle).to.be.ok;
                    expect(jsonKeyPairHandle.prv).to.be.ok;
                    expect(jsonKeyPairHandle.pub).to.be.ok;

                    const loadedKeyPairHandle = await CryptoSignatureKeypairHandle.fromJSON(jsonKeyPairHandle);
                    await expectCryptoSignatureKeypairHandle(loadedKeyPairHandle, "SoftwareProvider", spec);
                });

                it("toBase64() and fromBase64()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);

                    const encodedKeyPairHandle = cryptoKeyPairHandle.toBase64();
                    expect(encodedKeyPairHandle).to.be.ok.and.be.a("string");

                    const loadedKeyPairHandle = await CryptoSignatureKeypairHandle.fromBase64(encodedKeyPairHandle);
                    await expectCryptoSignatureKeypairHandle(loadedKeyPairHandle, "SoftwareProvider", spec);
                });

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
