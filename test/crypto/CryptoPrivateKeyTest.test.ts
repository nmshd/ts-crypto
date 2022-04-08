import { CryptoExchangeAlgorithm, CryptoPrivateKey } from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoPrivateKeyTest {
    public static run(): void {
        describe("CryptoPrivateKey", function () {
            describe("CryptoPrivateKey P521 ECDH", function () {
                const expectedBufferLength = 241;
                const expectedB64Length = 322;
                const expectedPEMLength = 392;
                const algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_P521;
                let importedPrivateKey: CryptoPrivateKey;
                let exportedPrivateKey: string;

                it("fromString() should import from Base64", function () {
                    const b64 =
                        "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBr3qwxJQ4sI2NEys3rvBIT3MMWS4JvdqX7ZpEcKWI3YdvNZXZMMzf_xj9PUcHw6EFW5y4ICj-g_NUhaB2pJOz4ZmhgYkDgYYABABwLiZbR5VFa38ecGDgKG9xgAorxIeo_8ZsIsOIJcLHSZJLF64Yzod5Pe8dn6nDIA1-kW74ixaK4PEWrnBw1rp3OAGzy2BJx7fy4R6pcKEXWlGIsjtKlIWGho1lLaKvuZaMnSjnwvRwNUYCGK5QYcLc_f0vxvPMRQZ82bJ-wkdKk7pAxw";
                    const privateKey = CryptoPrivateKey.fromString(b64, algorithm);
                    expect(privateKey).to.exist;
                    expect(privateKey).to.be.instanceOf(CryptoPrivateKey);
                    expect(privateKey.algorithm).to.exist;
                    expect(privateKey.privateKey).to.exist;
                    expect(privateKey.privateKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(privateKey.algorithm).to.be.equal(algorithm);
                    importedPrivateKey = privateKey;
                });

                it("fromPEM() should import from PEM", function () {
                    const b64 =
                        "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAi2KVeswxA67axJwc\nPGJEKawC8IM9LpPBK/P7ExZezam+WQ5lrJcrLV1lltZ+g5Ulwnrpk1GdA0WiZcdl\nYWaE0n6hgYkDgYYABACPab0wRy3VsrYfV649hWOcktFTLRpxwj6opR9wZPdWhWNz\nO5ufqomVxpPjoY12aspwy/bETnE4ONG/1shWlNL1YgA0+GQNKuT/XZ8WogNQn3Fv\n7lli4r0zfGhAkkodZ2x9PoymhHZVpHh1QkC1k05bbnaIwTa/tDGaj5CUVES5GJ1d\nIQ==\n-----END PRIVATE KEY-----\n";
                    const privateKey = CryptoPrivateKey.fromPEM(b64, algorithm);
                    expect(privateKey).to.exist;
                    expect(privateKey).to.be.instanceOf(CryptoPrivateKey);
                    expect(privateKey.algorithm).to.exist;
                    expect(privateKey.privateKey).to.exist;
                    expect(privateKey.privateKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(privateKey.algorithm).to.be.equal(algorithm);

                    importedPrivateKey = privateKey;
                });

                it("toString() should export to Base64", function () {
                    const exported = importedPrivateKey.toString();
                    expect(exported).to.be.of.length(expectedB64Length);
                    exportedPrivateKey = exported;
                    return exported;
                });

                it("fromString() should import again from Base64", function () {
                    const b64 = exportedPrivateKey;
                    const privateKey = CryptoPrivateKey.fromString(b64, algorithm);
                    expect(privateKey).to.exist;
                    expect(privateKey).to.be.instanceOf(CryptoPrivateKey);
                    expect(privateKey.algorithm).to.exist;

                    expect(privateKey.privateKey).to.exist;
                    expect(privateKey.privateKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(privateKey.algorithm).to.be.equal(algorithm);

                    importedPrivateKey = privateKey;
                });

                it("toPEM() should export to PEM", function () {
                    const exported = importedPrivateKey.toPEM();
                    expect(exported).to.be.of.length(expectedPEMLength);
                    exportedPrivateKey = exported;
                    return exported;
                });

                it("fromPEM() should import again from PEM", function () {
                    const b64 = exportedPrivateKey;
                    const privateKey = CryptoPrivateKey.fromPEM(b64, algorithm);
                    expect(privateKey).to.exist;
                    expect(privateKey).to.be.instanceOf(CryptoPrivateKey);
                    expect(privateKey.algorithm).to.exist;

                    expect(privateKey.privateKey).to.exist;
                    expect(privateKey.privateKey.buffer).to.be.of.length(expectedBufferLength);
                    expect(privateKey.algorithm).to.be.equal(algorithm);
                    importedPrivateKey = privateKey;
                });
            });
        });
    }
}
