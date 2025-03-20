/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoSignaturePrivateKeyHandle, CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { assertCryptoAsymmetricKeyHandle } from "../CryptoAsymmetricKeyHandle.test";
import { idSpecProviderNameEqual } from "../CryptoLayerTestUtil";

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

                it("toJSON() and fromJSON()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;

                    const serializedPrivateKeyHandle = privateKeyHandle.toJSON();
                    expect(serializedPrivateKeyHandle.cid).to.equal(id);
                    expect(serializedPrivateKeyHandle.pnm).to.equal(providerName);
                    expect(serializedPrivateKeyHandle.spc).to.deep.equal(spec);
                    expect(serializedPrivateKeyHandle["@type"]).to.equal("CryptoSignaturePrivateKeyHandle");

                    const loadedPrivateKeyHandle =
                        await CryptoSignaturePrivateKeyHandle.fromJSON(serializedPrivateKeyHandle);
                    assertCryptoAsymmetricKeyHandle(loadedPrivateKeyHandle);
                    await idSpecProviderNameEqual(loadedPrivateKeyHandle, id, spec, providerName);
                });

                it("toBase64() and fromBase64()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;
                    privateKeyHandle.keyPairHandle;

                    const serializedPrivateKey = privateKeyHandle.toBase64();
                    expect(serializedPrivateKey).to.be.ok;
                    const deserializedPrivateKey =
                        await CryptoSignaturePrivateKeyHandle.fromBase64(serializedPrivateKey);
                    assertCryptoAsymmetricKeyHandle(deserializedPrivateKey);
                    await idSpecProviderNameEqual(deserializedPrivateKey, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() ICryptoSignaturePrivateKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;

                    const loadedPrivateKeyHandle = await CryptoSignaturePrivateKeyHandle.from({
                        spec: spec,
                        id: id,
                        providerName: providerName
                    });
                    assertCryptoAsymmetricKeyHandle(loadedPrivateKeyHandle);
                    await idSpecProviderNameEqual(loadedPrivateKeyHandle, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() CryptoSignaturePrivateKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;

                    const loadedPrivateKeyHandle = await CryptoSignaturePrivateKeyHandle.from(privateKeyHandle);
                    assertCryptoAsymmetricKeyHandle(loadedPrivateKeyHandle);
                    await idSpecProviderNameEqual(loadedPrivateKeyHandle, id, spec, providerName);
                });
            });
        });
    }
}
