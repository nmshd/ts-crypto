import { CoreBuffer, CryptoDerivationHandle, CryptoEncryption, ProviderIdentifier } from "@nmshd/crypto";
import { Cipher, KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";

export class CryptoDerivationHandleTest {
    public static run() {
        describe("CryptoDerivationHandle", function () {
            const providerIdent: ProviderIdentifier = { providerName: "SoftwareProvider" };

            it("deriveKeyHandleFromBase", async function () {
                const ciphers: Cipher[] = ["AesGcm128", "AesGcm256", "XChaCha20Poly1305"];

                for (const cipher of ciphers) {
                    const spec: KeySpec = {
                        cipher,
                        signing_hash: "Sha2_512",
                        ephemeral: false
                    };
                    const keyHandle = await CryptoEncryption.generateKeyHandle(providerIdent, spec);

                    const derivedKey = await CryptoDerivationHandle.deriveKeyHandleFromBase(
                        keyHandle,
                        1234,
                        "testTest"
                    );

                    const derivedKey2 = await CryptoDerivationHandle.deriveKeyHandleFromBase(
                        keyHandle,
                        1234,
                        "testTest"
                    );

                    const encoder = new TextEncoder();
                    const payload = new CoreBuffer(encoder.encode("Hello World!"));

                    const encryptedPayload = await CryptoEncryption.encrypt(payload, derivedKey);

                    const decryptedPayload = await CryptoEncryption.decrypt(encryptedPayload, derivedKey2);

                    expect(decryptedPayload).to.deep.equal(payload);
                }
            });
        });
    }
}
