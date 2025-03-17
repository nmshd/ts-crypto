/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoSignaturePublicKeyHandle, CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { expectCryptoSignatureAsymmetricKeyHandle } from "./CryptoLayerTestUtil";

export class CryptoSignaturePublicKeyHandleTest {
    public static run(): void {
        describe("CryptoSignaturePublicKeyHandle", function () {
            describe("CryptoSignaturePublicKeyHandle SoftwareProvider P256 Sha2_512", function () {
                const spec: KeyPairSpec = {
                    asym_spec: "P256",
                    cipher: null,
                    signing_hash: "Sha2_512",
                    ephemeral: false,
                    non_exportable: true
                };
                const providerIdent = { providerName: "SoftwareProvider" };

                it("toJSON() and fromJSON()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const serializedpublicKeyHandle = publicKeyHandle.toJSON();
                    expect(serializedpublicKeyHandle).to.be.instanceOf(Object);
                    expect(serializedpublicKeyHandle.cid).to.equal(id);
                    expect(serializedpublicKeyHandle.pnm).to.equal(providerName);
                    expect(serializedpublicKeyHandle.spc).to.deep.equal(spec);
                    expect(serializedpublicKeyHandle["@type"]).to.equal("CryptoSignaturePublicKeyHandle");

                    const loadedpublicKeyHandle =
                        await CryptoSignaturePublicKeyHandle.fromJSON(serializedpublicKeyHandle);
                    await expectCryptoSignatureAsymmetricKeyHandle(loadedpublicKeyHandle, id, spec, providerName);
                });

                it("toBase64() and fromBase64()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const serializedpublicKey = publicKeyHandle.toBase64();
                    expect(serializedpublicKey).to.be.ok;
                    const deserializedpublicKey = CryptoSignaturePublicKeyHandle.fromBase64(serializedpublicKey);
                    await expectCryptoSignatureAsymmetricKeyHandle(await deserializedpublicKey, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() ICryptoSignaturePublicKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const loadedpublicKeyHandle = await CryptoSignaturePublicKeyHandle.from({
                        spec: spec,
                        id: id,
                        providerName: providerName
                    });
                    await expectCryptoSignatureAsymmetricKeyHandle(loadedpublicKeyHandle, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() CryptoSignaturePublicKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const loadedpublicKeyHandle = await CryptoSignaturePublicKeyHandle.from(publicKeyHandle);
                    await expectCryptoSignatureAsymmetricKeyHandle(loadedpublicKeyHandle, id, spec, providerName);
                });
            });
        });
    }
}
