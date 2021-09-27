import { CryptoError, CryptoErrorCode, CryptoPasswordGenerator, CryptoRandomCharacterRange } from "@nmshd/crypto";
import { expect } from "chai";

const expectThrowsAsync = async (method: Function | Promise<any>, errorMessage = "") => {
    let error = null;
    try {
        if (typeof method === "function") {
            await method();
        } else {
            await method;
        }
    } catch (err: any) {
        error = err;
    }
    expect(error).to.be.an("Error");
    expect(error).to.be.instanceOf(CryptoError);
    if (errorMessage) {
        expect(error.code).to.equal(errorMessage);
    }
};

export class CryptoPasswordGeneratorTest {
    public static run(): void {
        const iterations = 20;
        describe("PasswordGeneratorTest", function () {
            describe("Execute createPassword()", function () {
                it("should return a fixed length password", async function () {
                    let pass;
                    for (let i = 1; i < iterations; i++) {
                        pass = await CryptoPasswordGenerator.createPassword(i);
                        expect(pass).to.be.of.length(i);
                    }
                });

                it("should return a random length password within the range", async function () {
                    let pass;
                    for (let i = 1; i < iterations; i++) {
                        pass = await CryptoPasswordGenerator.createPassword(6, 10);
                        expect(pass.length).to.be.within(6, 10);
                    }
                });
            });

            describe("Execute createStrongPassword()", function () {
                it("should return a random password with a dynamic size", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createStrongPassword();
                        expect(pass.length).to.be.within(10, 20);
                    }
                });
                it("should return a random password with the correct given length (1)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createStrongPassword(50, 50);
                        expect(pass).to.be.length(50);
                    }
                });
                it("should return a random password with the correct given length (2)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createStrongPassword(20, 50);
                        expect(pass.length).to.be.within(20, 50);
                    }
                });
                it("should throw an error if minLength is too low", async function () {
                    for (let i = 1; i < iterations; i++) {
                        await expectThrowsAsync(
                            CryptoPasswordGenerator.createStrongPassword(2, 20),
                            CryptoErrorCode.PasswordInsecure
                        );
                    }
                });
            });

            describe("Execute createUnitPassword()", function () {
                it("should return a random password", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createUnitPassword();
                        expect(pass.length).to.be.within(5, 30);
                    }
                });
            });

            describe("Execute createPasswordWithBitStrength()", function () {
                it("should return a password of 44 characters for 256bit (with AlphanumericEase character range)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.AlphanumericEase,
                            256,
                            0
                        );
                        expect(pass.length).to.equal(44);
                    }
                });

                it("should return a password of 22 characters for 128bit (with AlphanumericEase character range)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.AlphanumericEase,
                            128,
                            0
                        );
                        expect(pass.length).to.equal(22);
                    }
                });

                it("should return a password of 16 characters for 96bit (with AlphanumericEase character range)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.AlphanumericEase,
                            96,
                            0
                        );
                        expect(pass.length).to.equal(16);
                    }
                });

                it("should return a password of around 44 characters for 256bit (delta of 2) (with AlphanumericEase character range)", async function () {
                    const length = 44;
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.AlphanumericEase,
                            256,
                            0
                        );
                        expect(pass.length).to.be.within(length - 2, length + 2);
                    }
                });

                it("should return a password of around 22 characters for 128bit (delta of 2) (with AlphanumericEase character range)", async function () {
                    const length = 22;
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.AlphanumericEase,
                            128,
                            0
                        );
                        expect(pass.length).to.be.within(length - 2, length + 2);
                    }
                });

                it("should return a password of around 16 characters for 96bit (delta of 2) (with AlphanumericEase character range)", async function () {
                    const length = 16;
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.AlphanumericEase,
                            96,
                            0
                        );
                        expect(pass.length).to.be.within(length - 2, length + 2);
                    }
                });

                it("should return a password of 77 characters for 256bit (with digit character range)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.Digit,
                            256,
                            0
                        );
                        expect(pass.length).to.equal(77);
                    }
                });

                it("should return a password of 39 characters for 128bit (with digit character range)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.Digit,
                            128,
                            0
                        );
                        expect(pass.length).to.equal(39);
                    }
                });

                it("should return a password of 29 characters for 96bit (with digit character range)", async function () {
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.Digit,
                            96,
                            0
                        );
                        expect(pass.length).to.equal(29);
                    }
                });

                it("should return a password of around 77 characters for 256bit (delta of 2) (with digit character range)", async function () {
                    const length = 77;
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.Digit,
                            256,
                            0
                        );
                        expect(pass.length).to.be.within(length - 2, length + 2);
                    }
                });

                it("should return a password of around 39 characters for 128bit (delta of 2) (with digit character range)", async function () {
                    const length = 39;
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.Digit,
                            128,
                            0
                        );
                        expect(pass.length).to.be.within(length - 2, length + 2);
                    }
                });

                it("should return a password of around 29 characters for 96bit (delta of 2) (with digit character range)", async function () {
                    const length = 29;
                    for (let i = 1; i < iterations; i++) {
                        const pass = await CryptoPasswordGenerator.createPasswordWithBitStrength(
                            CryptoRandomCharacterRange.Digit,
                            96,
                            0
                        );
                        expect(pass.length).to.be.within(length - 2, length + 2);
                    }
                });
            });
        });
    }
}
