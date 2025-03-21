/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoSignaturePrivateKeyHandle, CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { TestSerializeDeserializeOfAsymmetricKeyPairHandle } from "../CommonSerialize";
import { idSpecProviderNameEqual } from "../CryptoLayerTestUtil";
import { assertAsymmetricKeyHandleValid } from "../KeyValidation";

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

                TestSerializeDeserializeOfAsymmetricKeyPairHandle(
                    "CryptoSignaturePrivateKeyHandle",
                    async () => (await CryptoSignatures.generateKeypairHandle(providerIdent, spec)).privateKey,
                    CryptoSignaturePrivateKeyHandle
                );

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
                    await assertAsymmetricKeyHandleValid(loadedPrivateKeyHandle);
                    await idSpecProviderNameEqual(loadedPrivateKeyHandle, id, spec, providerName);
                });

                // eslint-disable-next-line jest/expect-expect
                it("from() CryptoSignaturePrivateKeyHandle", async function () {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                    const privateKeyHandle = cryptoKeyPairHandle.privateKey;
                    const id = privateKeyHandle.id;
                    const providerName = privateKeyHandle.providerName;

                    const loadedPrivateKeyHandle = await CryptoSignaturePrivateKeyHandle.from(privateKeyHandle);
                    await assertAsymmetricKeyHandleValid(loadedPrivateKeyHandle);
                    await idSpecProviderNameEqual(loadedPrivateKeyHandle, id, spec, providerName);
                });
            });
        });
    }
}
