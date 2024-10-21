import {
    CoreBuffer,
    CryptoDerivation,
    CryptoDerivationAlgorithm,
    CryptoEncryptionAlgorithm,
    CryptoHash,
    CryptoHashAlgorithm,
    CryptoSecretKey,
    Encoding,
    ICoreBuffer
} from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoDerivationTest {
    public static run(): void {
        describe("CryptoDerivation", function () {
            describe("Execute deriveKeyFromBase()", function () {
                let keybuffer: ICoreBuffer;
                before(async function () {
                    // Create 256bit entropy
                    keybuffer = await CryptoHash.hash(
                        CoreBuffer.fromString("test", Encoding.Utf8),
                        CryptoHashAlgorithm.SHA256
                    );
                });

                it("should derive the same key of same input", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromBase(keybuffer, 0, "12345678");
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiJfdkg4NkdJeU12cFdnZkJ2Y09FY0dfNHRhakpiVXJ5cGRUWW9iZl9jb0Y4IiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const derivedComparison = await CryptoDerivation.deriveKeyFromBase(keybuffer, 0, "12345678");
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJfdkg4NkdJeU12cFdnZkJ2Y09FY0dfNHRhakpiVXJ5cGRUWW9iZl9jb0Y4IiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.equal(derivedComparison.toBase64());
                });

                it("should derive different keys of different input (basekey)", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromBase(keybuffer, 0, "12345678");
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiJfdkg4NkdJeU12cFdnZkJ2Y09FY0dfNHRhakpiVXJ5cGRUWW9iZl9jb0Y4IiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const keybuffer2 = await CryptoHash.hash(
                        CoreBuffer.fromString("test2", Encoding.Utf8),
                        CryptoHashAlgorithm.SHA256
                    );
                    const derivedComparison = await CryptoDerivation.deriveKeyFromBase(keybuffer2, 0, "12345678");
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJna0RvRTFFWjNnRHBxb3VxalNRcjJ3UzB1Wms5dzRSTkdlNkZDZkRodnBZIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.not.equal(derivedComparison.toBase64());
                });

                it("should derive different keys of different input (context)", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromBase(keybuffer, 0, "12345678");
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiJfdkg4NkdJeU12cFdnZkJ2Y09FY0dfNHRhakpiVXJ5cGRUWW9iZl9jb0Y4IiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const derivedComparison = await CryptoDerivation.deriveKeyFromBase(keybuffer, 0, "x2345678");
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJjY3Nsenk2eml5NnVJdVRocHVmaWZvV1cybzBIYmFPNlFFUXR1ZTRJOS1ZIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.not.equal(derivedComparison.toBase64());
                });

                it("should derive different keys of different input (keyId)", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromBase(keybuffer, 0, "12345678");
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiJfdkg4NkdJeU12cFdnZkJ2Y09FY0dfNHRhakpiVXJ5cGRUWW9iZl9jb0Y4IiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const derivedComparison = await CryptoDerivation.deriveKeyFromBase(keybuffer, 1, "12345678");
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJlMlNpUGlkMEtITVV2RzZzZ2VIX2FDM1hHTWJtd3ZuYnAzbXVvY3JMSEVBIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.not.equal(derivedComparison.toBase64());
                });
            });

            describe("Execute deriveKeyFromPassword()", function () {
                let master: ICoreBuffer;
                let salt: ICoreBuffer;
                before(async function () {
                    // Create 256bit entropy
                    master = CoreBuffer.fromUtf8("test");
                    salt = CoreBuffer.from(
                        (
                            await CryptoHash.hash(
                                CoreBuffer.fromString("test", Encoding.Utf8),
                                CryptoHashAlgorithm.SHA256
                            )
                        ).buffer.subarray(0, 16)
                    );
                });

                it("should derive the same key of same input", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        10
                    );
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiI5ck1uY2NOODlsRVpXNVJuQWdpWWk4Tm9xY21vOWIyMmFYQmpuMTlRV0ZRIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const derivedComparison = await await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        10
                    );
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiI5ck1uY2NOODlsRVpXNVJuQWdpWWk4Tm9xY21vOWIyMmFYQmpuMTlRV0ZRIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.equal(derivedComparison.toBase64());
                });

                it("should derive different keys of different input (master)", async function () {
                    const derived = await await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        10
                    );
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiI5ck1uY2NOODlsRVpXNVJuQWdpWWk4Tm9xY21vOWIyMmFYQmpuMTlRV0ZRIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const master2 = CoreBuffer.fromString("test2", Encoding.Utf8);
                    const derivedComparison = await CryptoDerivation.deriveKeyFromPassword(
                        master2,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        10
                    );
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJZaUNROFlTUkd2YmNUMExZeWU0NkxqZ0EySkpEaEVIQjRoNEU0ZmJjSlFNIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.not.equal(derivedComparison.toBase64());
                });

                it("should derive different keys of different input (salt)", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        10
                    );
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiI5ck1uY2NOODlsRVpXNVJuQWdpWWk4Tm9xY21vOWIyMmFYQmpuMTlRV0ZRIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const salt2 = CoreBuffer.from(
                        (
                            await CryptoHash.hash(
                                CoreBuffer.fromString("test2", Encoding.Utf8),
                                CryptoHashAlgorithm.SHA256
                            )
                        ).buffer.subarray(0, 16)
                    );
                    const derivedComparison = await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt2,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        10
                    );
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJiaGxybXZPdUxZWUZMVXpRaVh5VHdrTjl4Z1RNZlVhOFN3SDdQcU1nWnFVIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.not.equal(derivedComparison.toBase64());
                });

                it("should derive different keys of different input (iterations)", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        1
                    );
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiI4OE1XZWItdXlQRkhkOWJRZENJY05iSHlpbXFhUUo2TXdfekxxemdBTjQwIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    const derivedComparison = await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        2
                    );
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJiTDVYWkM3YTBEQWhUS1g4T2JsZVR0Mk0yNXJhOXctOGdnYmJ0eHRrdndRIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.not.equal(derivedComparison.toBase64());
                });

                it("should derive different keys of different input (memlimit)", async function () {
                    const derived = await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        1,
                        8192
                    );
                    expect(derived).to.be.instanceOf(CryptoSecretKey);
                    expect(derived.toBase64()).to.equal(
                        "eyJrZXkiOiI4OE1XZWItdXlQRkhkOWJRZENJY05iSHlpbXFhUUo2TXdfekxxemdBTjQwIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    //Careful here - increasing memlimit too little does not change the derived key
                    const derivedComparison = await CryptoDerivation.deriveKeyFromPassword(
                        master,
                        salt,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoDerivationAlgorithm.ARGON2ID,
                        1,
                        8192 * 2
                    );
                    expect(derivedComparison).to.be.instanceOf(CryptoSecretKey);
                    expect(derivedComparison.toBase64()).to.equal(
                        "eyJrZXkiOiJVV05obGtua0U0Tmx5bWUtdUh4c2x4M09MbzBjTjUtSGdFV0dtdHJpQmVrIiwiYWxnIjozLCJAdHlwZSI6IkNyeXB0b1NlY3JldEtleSJ9"
                    );

                    expect(derived.toBase64()).to.not.equal(derivedComparison.toBase64());
                });
            });
        });
    }
}
