/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoHashAlgorithm, CryptoSignature } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoSignaturePrivateKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePrivateKeyHandle";
import { CryptoSignatures } from "src/signature/CryptoSignatures";

export async function expectCryptoSignaturePrivateKeyHandle(
    value: CryptoSignaturePrivateKeyHandle,
    id: string,
    spec: KeyPairSpec,
    providerName: string
): Promise<void> {
    expect(value).to.be.instanceOf(CryptoSignaturePrivateKeyHandle);
    expect(value.id).to.equal(id);
    expect(value.providerName).to.equal(providerName);
    expect(value.spec).to.deep.equal(spec);
    expect(value.keyPairHandle).to.be.ok;
    expect(value.provider).to.be.ok;
    expect(await value.keyPairHandle.id()).to.equal(id);
    expect(await value.provider.providerName()).to.equal(providerName);
}

export class CryptoSignaturePrivateKeyHandleTest {
    public static run(): void {
        describe("CryptoSignaturePrivateKeyHandle", function () {
            describe("CryptoSignaturePrivateKeyHandle SoftwareProvider P256 Sha2_512", function () {
                const spec: KeyPairSpec = {
                    asym_spec: "P256",
                    cipher: null,
                    signing_hash: "Sha2_512",
                    ephemeral: false,
                    non_exportable: false
                };
                const providerIdent = { providerName: "SoftwareProvider" };

                it("sign and verify", async function () {
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

                it("toJSON and fromJSON", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;

                    const serializedPrivateKeyHandle = privateKeyHandle.toJSON();
                    expect(serializedPrivateKeyHandle).to.be.instanceOf(Object);
                    expect(serializedPrivateKeyHandle.cid).to.equal(id);
                    expect(serializedPrivateKeyHandle.pnm).to.equal(providerName);
                    expect(serializedPrivateKeyHandle.spc).to.deep.equal(spec);
                    expect(serializedPrivateKeyHandle["@type"]).to.equal("CryptoSignaturePrivateKeyHandle");

                    const loadedPrivateKeyHandle =
                        await CryptoSignaturePrivateKeyHandle.fromJSON(serializedPrivateKeyHandle);
                    await expectCryptoSignaturePrivateKeyHandle(loadedPrivateKeyHandle, id, spec, providerName);
                });

                it("toBase64 and fromBase64", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;

                    const serializedPrivateKey = privateKeyHandle.toBase64();
                    expect(serializedPrivateKey).to.be.ok;
                    const deserializedPrivateKey = CryptoSignaturePrivateKeyHandle.fromBase64(serializedPrivateKey);
                    await expectCryptoSignaturePrivateKeyHandle(await deserializedPrivateKey, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;

                    const loadedPrivateKeyHandle = await CryptoSignaturePrivateKeyHandle.from({
                        spec: spec,
                        id: id,
                        providerName: providerName
                    });
                    await expectCryptoSignaturePrivateKeyHandle(loadedPrivateKeyHandle, id, spec, providerName);
                });
            });
        });
    }
}
