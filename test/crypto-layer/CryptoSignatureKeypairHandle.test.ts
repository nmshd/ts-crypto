/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { CryptoSignatureKeypairHandle } from "src/crypto-layer/signature/CryptoSignatureKeypair";
import { CryptoSignaturePrivateKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePrivateKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePublicKeyHandle";

export class CryptoSignatureKeypairHandleTest {
    public static run(): void {
        describe("CryptoSignatureKeypairHandle", function () {
            describe("generateKeyPairHandle() SoftwareProvider", function () {
                it("generateKeyPairHandle() with P256", async function () {
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
                    expect(cryptoKeyPairHandle).to.exist;
                    expect(cryptoKeyPairHandle).to.be.instanceOf(CryptoSignatureKeypairHandle);
                    expect(cryptoKeyPairHandle.privateKey).to.exist;
                    expect(cryptoKeyPairHandle.publicKey).to.exist;
                    expect(cryptoKeyPairHandle.privateKey).to.be.instanceOf(CryptoSignaturePrivateKeyHandle);
                    expect(cryptoKeyPairHandle.publicKey).to.be.instanceOf(CryptoSignaturePublicKeyHandle);
                    expect(cryptoKeyPairHandle.privateKey.keyPairHandle).to.exist;
                    expect(cryptoKeyPairHandle.publicKey.keyPairHandle).to.exist;
                    expect(cryptoKeyPairHandle.privateKey.keyPairHandle).to.be.equal(
                        cryptoKeyPairHandle.publicKey.keyPairHandle
                    );
                    expect(cryptoKeyPairHandle.privateKey.id).to.exist;
                    expect(cryptoKeyPairHandle.publicKey.id).to.exist;
                    expect(cryptoKeyPairHandle.privateKey.id).to.be.string(cryptoKeyPairHandle.publicKey.id);
                    expect(cryptoKeyPairHandle.privateKey.provider).to.exist;
                    expect(cryptoKeyPairHandle.publicKey.provider).to.exist;
                    expect(cryptoKeyPairHandle.privateKey.provider).to.equal(cryptoKeyPairHandle.publicKey.provider);
                    expect(cryptoKeyPairHandle.privateKey.providerName).to.exist;
                    expect(cryptoKeyPairHandle.publicKey.providerName).to.exist;
                    expect(cryptoKeyPairHandle.privateKey.providerName).to.be.string(
                        cryptoKeyPairHandle.publicKey.providerName
                    );
                    expect(cryptoKeyPairHandle.privateKey.providerName).to.be.string("SoftwareProvider");
                    expect(await cryptoKeyPairHandle.privateKey.keyPairHandle.id()).to.be.string(
                        cryptoKeyPairHandle.privateKey.id
                    );
                });
            });
        });
    }
}
