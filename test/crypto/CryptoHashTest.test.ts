import { CryptoHash, ICryptoHash } from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoHashTest {
    public static run(): void {
        describe("CryptoHash", function () {
            describe("Execute hash() with SHA256", function () {
                let h1: ICryptoHash;
                let h2: ICryptoHash;
                before(async function () {
                    h1 = await CryptoHash.sha256("test");
                    h2 = await CryptoHash.sha256("test");
                });

                it("should return a SecretKey", function () {
                    expect(h1).to.exist;
                    expect(h1).to.be.equal(h2);
                });
            });

            describe("Execute hash() with SHA512", function () {
                let h1: ICryptoHash;
                let h2: ICryptoHash;
                before(async function () {
                    h1 = await CryptoHash.sha512("test");
                    h2 = await CryptoHash.sha512("test");
                });

                it("should return a SecretKey", function () {
                    expect(h1).to.exist;
                    expect(h1).to.be.equal(h2);
                });
            });
        });
    }
}
