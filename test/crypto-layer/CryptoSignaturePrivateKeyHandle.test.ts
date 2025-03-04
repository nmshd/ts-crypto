/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoHashAlgorithm, CryptoSignature } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoSignatures } from "src/signature/CryptoSignatures";
import { expectCryptoSignatureKeypairHandle } from "./CryptoSignatureKeypairHandle.test";

export class CryptoSignaturePrivateKeyHandleTest {
    public static run(): void {
        describe("CryptoSignaturePrivateKeyHandle", function () {
            describe("sign() with SoftwareProvider", function () {
                it("sign() and verify() with P256", async function () {
                    const spec: KeyPairSpec = {
                        asym_spec: "P256",
                        cipher: null,
                        signing_hash: "Sha2_512",
                        ephemeral: false,
                        non_exportable: false
                    };
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(
                        { providerName: "SoftwareProvider" },
                        spec
                    );
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);

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
