import { CoreBuffer, CryptoExportedPublicKey, CryptoPublicKeyHandle, CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { expectCryptoSignatureAsymmetricKeyHandle } from "./CryptoLayerTestUtil";

/* eslint-disable @typescript-eslint/naming-convention */
export class CryptoExportedPublicKeyTest {
    public static run(): void {
        describe("CryptoExportedPublicKey", function () {
            const spec: KeyPairSpec = {
                asym_spec: "P256",
                cipher: null,
                signing_hash: "Sha2_512",
                ephemeral: false,
                non_exportable: false
            };

            const providerIdent = { providerName: "SoftwareProvider" };
            it("from and to CryptoPublicKeyHandle", async function () {
                const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                const id = publicKeyHandle.id;
                await expectCryptoSignatureAsymmetricKeyHandle(publicKeyHandle, id, spec, providerIdent.providerName);

                const exportedPublicKey = await CryptoExportedPublicKey.from(publicKeyHandle);
                expect(exportedPublicKey.rawPublicKey).to.be.instanceOf(CoreBuffer);
                expect(exportedPublicKey.spec).to.be.deep.equal(publicKeyHandle.spec);

                const importedPublicKey = await exportedPublicKey.into(CryptoPublicKeyHandle, providerIdent);
                expect(importedPublicKey).to.be.ok.and.to.be.instanceOf(CryptoPublicKeyHandle);
                expect(await importedPublicKey.keyPairHandle.getPublicKey()).to.deep.equal(
                    await publicKeyHandle.keyPairHandle.getPublicKey()
                );
                expect(importedPublicKey.spec).to.deep.equal(publicKeyHandle.spec);
            });
        });
    }
}
