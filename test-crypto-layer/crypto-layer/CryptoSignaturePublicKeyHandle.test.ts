/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoSignaturePublicKeyHandle, CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { assertCryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle.test";
import { idSpecProviderNameEqual } from "./CryptoLayerTestUtil";

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

                    const serializedPublicKeyHandle = publicKeyHandle.toJSON();
                    expect(serializedPublicKeyHandle).to.be.instanceOf(Object);
                    expect(serializedPublicKeyHandle.cid).to.equal(id);
                    expect(serializedPublicKeyHandle.pnm).to.equal(providerName);
                    expect(serializedPublicKeyHandle.spc).to.deep.equal(spec);
                    expect(serializedPublicKeyHandle["@type"]).to.equal("CryptoSignaturePublicKeyHandle");

                    const loadedPublicKeyHandle =
                        await CryptoSignaturePublicKeyHandle.fromJSON(serializedPublicKeyHandle);
                    assertCryptoAsymmetricKeyHandle(loadedPublicKeyHandle);
                    await idSpecProviderNameEqual(loadedPublicKeyHandle, id, spec, providerName);
                });

                it("toBase64() and fromBase64()", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const serializedPublicKey = publicKeyHandle.toBase64();
                    expect(serializedPublicKey).to.be.ok;
                    const deserializedPublicKey = CryptoSignaturePublicKeyHandle.fromBase64(serializedPublicKey);
                    assertCryptoAsymmetricKeyHandle(await deserializedPublicKey);
                    await idSpecProviderNameEqual(await deserializedPublicKey, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() ICryptoSignaturePublicKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const loadedPublicKeyHandle = await CryptoSignaturePublicKeyHandle.from({
                        spec: spec,
                        id: id,
                        providerName: providerName
                    });
                    assertCryptoAsymmetricKeyHandle(loadedPublicKeyHandle);
                    await idSpecProviderNameEqual(loadedPublicKeyHandle, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() CryptoSignaturePublicKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const loadedPublicKeyHandle = await CryptoSignaturePublicKeyHandle.from(publicKeyHandle);
                    assertCryptoAsymmetricKeyHandle(loadedPublicKeyHandle);
                    await idSpecProviderNameEqual(loadedPublicKeyHandle, id, spec, providerName);
                });
            });
        });
    }
}
