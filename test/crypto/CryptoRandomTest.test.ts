import { CryptoRandom, CryptoRandomCharacterRange } from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoRandomTest {
    public static run(): void {
        describe("RandomTest", function () {
            describe("Execute intBetween()", function () {
                it("should return a number between the min and max", async function () {
                    let n;
                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.intBetween(0, 1);
                        expect(n).to.be.lessThan(2);
                        expect(n).to.be.greaterThan(-1);
                    }
                });

                it("should return an even number across all possible values (0|1)", async function () {
                    let n;
                    let buckets: number[] = [];
                    const iterations = 10000;
                    buckets = [0, 0];
                    for (let i = 1; i < iterations; i++) {
                        n = await CryptoRandom.intBetween(0, 1);
                        switch (n) {
                            case 0:
                                buckets[0]++;
                                break;
                            case 1:
                                buckets[1]++;
                                break;
                            default:
                                throw new Error(`Value ${n} is not in the range!`);
                        }
                    }

                    expect(buckets[0]).to.be.lessThan(iterations * 0.6);
                    expect(buckets[0]).to.be.greaterThan(iterations * 0.4);
                    expect(buckets[1]).to.be.lessThan(iterations * 0.6);
                    expect(buckets[1]).to.be.greaterThan(iterations * 0.4);
                });

                it("should return an even number across all possible values (0 to 100)", async function () {
                    let n;
                    const buckets: number[] = [];
                    const iterations = 10000;
                    const min = 0;
                    const max = 100;
                    const diff = max - min + 1;

                    for (let j = 0; j < diff; j++) {
                        buckets[j] = 0;
                    }

                    for (let i = 1; i < iterations; i++) {
                        n = await CryptoRandom.intBetween(min, max);
                        buckets[n]++;
                    }

                    for (let j = 0; j < diff; j++) {
                        expect(buckets[j]).to.be.lessThan((iterations / diff) * 1.5);
                        expect(buckets[j]).to.be.greaterThan((iterations / diff) * 0.5);
                    }
                });

                it("should return a number between the min and max (1)", async function () {
                    let n;
                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.intBetween(-20, 20);
                        expect(n).to.be.lessThan(21);
                        expect(n).to.be.greaterThan(-21);
                    }
                });

                it("should return a number between the min and max (2)", async function () {
                    let n;
                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.intBetween(0, 2 ^ (32 - 1));
                        expect(n).to.be.lessThan(2 ^ 32);
                        expect(n).to.be.greaterThan(-1);
                    }
                });

                it("should return a number between the min and max (3)", async function () {
                    let n;
                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.intBetween((-1 * 2) ^ (32 + 1), 0);
                        expect(n).to.be.lessThan(1);
                        expect(n).to.be.greaterThan((-1 * 2) ^ 32);
                    }
                });
            });

            describe("Execute scramble()", function () {
                it("should return a string with the same length", async function () {
                    let n;
                    for (let i = 1; i < 20; i++) {
                        const instring = "012345";
                        n = await CryptoRandom.scramble(instring);
                        expect(n).to.be.of.length(instring.length);
                    }
                });
            });

            describe("Execute string()", function () {
                this.timeout(5000);

                it("should return a string with a fixed length", async function () {
                    let n;
                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.string(1);
                        expect(n).to.be.of.length(1);
                    }

                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.string(10);
                        expect(n).to.be.of.length(10);
                    }

                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.string(100);
                        expect(n).to.be.of.length(100);
                    }
                });

                it("should return a string with a fixed length and wanted characters", async function () {
                    let n;
                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.string(1, "a");
                        expect(n).to.be.of.length(1);
                        expect(n).to.equal("a");
                    }

                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.string(10, "a");
                        expect(n).to.be.of.length(10);
                        expect(n).to.equal("aaaaaaaaaa");
                    }

                    for (let i = 1; i < 20; i++) {
                        n = await CryptoRandom.string(10, "0");
                        expect(n).to.be.of.length(10);
                        expect(n).to.equal("0000000000");
                    }
                });

                it("should return an even number across all possible values (Alphabet)", async function () {
                    let n;
                    const buckets: any = {};
                    const iterations = 10000;
                    const diff = CryptoRandomCharacterRange.Alphabet.length;

                    for (let i = 1; i < iterations; i++) {
                        n = await CryptoRandom.string(1, CryptoRandomCharacterRange.Alphabet);
                        if (buckets[n]) buckets[n]++;
                        else buckets[n] = 1;
                    }

                    for (const char in buckets) {
                        expect(buckets[char]).to.be.lessThan((iterations / diff) * 1.5);
                        expect(buckets[char]).to.be.greaterThan((iterations / diff) * 0.5);
                    }
                });
            });
        });
    }
}
