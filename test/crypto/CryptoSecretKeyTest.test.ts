import { CryptoEncryptionAlgorithm, CryptoSecretKey } from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoSecretKeyTest {
    public static run(): void {
        describe("CryptoSecretKey", function () {
            context("XCHACHA20_POLY1305", function () {
                const expectedBufferLength = 32;
                const expectedB64Length = 43;
                const algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;
                let importedSecretKey: CryptoSecretKey;

                it("fromString() should import from Base64", function () {
                    const b64 = "AUio8cs62qJhmra6W1TXgwK0Y1wWo7cpywebexmANnI";
                    const privateKey = CryptoSecretKey.fromJSON({
                        key: b64,
                        alg: algorithm
                    });
                    expect(privateKey).to.exist;
                    expect(privateKey).to.be.instanceOf(CryptoSecretKey);
                    expect(privateKey.algorithm).to.exist;
                    expect(privateKey.secretKey).to.exist;
                    expect(privateKey.secretKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(privateKey.algorithm).to.be.equal(algorithm);
                    importedSecretKey = privateKey;
                });

                it("toString() should export to Base64", function () {
                    const exported = importedSecretKey.secretKey.toBase64URL();
                    expect(exported).to.be.of.length(expectedB64Length);
                    return exported;
                });
            });
        });
    }
}
