import { CryptoExchangeAlgorithm, CryptoPublicKey } from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoPublicKeyTest {
    public static run(): void {
        describe("CryptoPublicKey", function () {
            describe("CryptoPublicKey P521 ECDH", function () {
                const expectedBufferLength = 133;
                const expectedB64Length = 178;
                const expectedPEMLength = 240;
                const algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_X25519;
                let importedPublicKey: CryptoPublicKey;
                let exportedPublicKey: string;

                it("fromString() should import from Base64", function () {
                    const b64 =
                        "BADDh0-KAUSWqYqrqqEgEF6mkf_bTytaABRCodaKIHvbfVWw89zrhiga-YdaezEZ6hwVdTT_s8YGieliNui4Z9EOAgDtyi2SdkBp6ydBN5jh04vLVFTVXuPkitaWzsymM8oN4pkTgiXgDN7jgHh7E_0SCrf2lgWBH-wWW9uifW0Ic1Y-ZA";
                    const publicKey = CryptoPublicKey.fromString(b64, algorithm);
                    expect(publicKey).to.exist;
                    expect(publicKey).to.be.instanceOf(CryptoPublicKey);
                    expect(publicKey.algorithm).to.exist;
                    expect(publicKey.publicKey).to.exist;
                    expect(publicKey.publicKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(publicKey.algorithm).to.be.equal(algorithm);
                    importedPublicKey = publicKey;
                });

                it("fromPEM() should import from PEM", function () {
                    const b64 =
                        "-----BEGIN PUBLIC KEY-----\r\nBADDh0+KAUSWqYqrqqEgEF6mkf/bTytaABRCodaKIHvbfVWw89zrhiga+YdaezEZ\r\n6hwVdTT/s8YGieliNui4Z9EOAgDtyi2SdkBp6ydBN5jh04vLVFTVXuPkitaWzsym\r\nM8oN4pkTgiXgDN7jgHh7E/0SCrf2lgWBH+wWW9uifW0Ic1Y+ZA==\r\n-----END PUBLIC KEY-----\r\n";
                    const publicKey = CryptoPublicKey.fromPEM(b64, algorithm);
                    expect(publicKey).to.exist;
                    expect(publicKey).to.be.instanceOf(CryptoPublicKey);
                    expect(publicKey.algorithm).to.exist;
                    expect(publicKey.publicKey).to.exist;
                    expect(publicKey.publicKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(publicKey.algorithm).to.be.equal(algorithm);
                    importedPublicKey = publicKey;
                });

                it("toString() should export to Base64", function () {
                    const exported = importedPublicKey.toString();
                    expect(exported).to.be.of.length(expectedB64Length);
                    exportedPublicKey = exported;
                    return exported;
                });

                it("fromString() should import again from Base64", function () {
                    const b64 = exportedPublicKey;
                    const publicKey = CryptoPublicKey.fromString(b64, algorithm);
                    expect(publicKey).to.exist;
                    expect(publicKey).to.be.instanceOf(CryptoPublicKey);
                    expect(publicKey.algorithm).to.exist;

                    expect(publicKey.publicKey).to.exist;
                    expect(publicKey.publicKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(publicKey.algorithm).to.be.equal(algorithm);
                    importedPublicKey = publicKey;
                });

                it("toPEM() should export to PEM", function () {
                    const exported = importedPublicKey.toPEM();
                    expect(exported).to.be.of.length(expectedPEMLength);
                    exportedPublicKey = exported;
                    return exported;
                });

                it("fromPEM() should import again from PEM", function () {
                    const b64 = exportedPublicKey;
                    const publicKey = CryptoPublicKey.fromPEM(b64, algorithm);
                    expect(publicKey).to.exist;
                    expect(publicKey).to.be.instanceOf(CryptoPublicKey);
                    expect(publicKey.algorithm).to.exist;
                    expect(publicKey.publicKey).to.exist;
                    expect(publicKey.publicKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(publicKey.algorithm).to.be.equal(algorithm);
                    importedPublicKey = publicKey;
                });
            });
        });
    }
}
