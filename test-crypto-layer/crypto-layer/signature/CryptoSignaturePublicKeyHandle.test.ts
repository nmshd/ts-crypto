/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoSignaturePublicKeyHandle, CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { TestSerializeDeserializeOfAsymmetricKeyPairHandle } from "../CommonSerialize";
import { idSpecProviderNameEqual } from "../CryptoLayerTestUtil";
import { assertAsymmetricKeyHandleValid } from "../KeyValidation";

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

                TestSerializeDeserializeOfAsymmetricKeyPairHandle(
                    "CryptoSignaturePublicKeyHandle",
                    async () => (await CryptoSignatures.generateKeypairHandle(providerIdent, spec)).publicKey,
                    CryptoSignaturePublicKeyHandle
                );

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
                    assertAsymmetricKeyHandleValid(loadedPublicKeyHandle);
                    await idSpecProviderNameEqual(loadedPublicKeyHandle, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() CryptoSignaturePublicKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                    const id = publicKeyHandle.id;
                    const providerName = publicKeyHandle.providerName;

                    const loadedPublicKeyHandle = await CryptoSignaturePublicKeyHandle.from(publicKeyHandle);
                    assertAsymmetricKeyHandleValid(loadedPublicKeyHandle);
                    await idSpecProviderNameEqual(loadedPublicKeyHandle, id, spec, providerName);
                });
            });
        });
    }
}
