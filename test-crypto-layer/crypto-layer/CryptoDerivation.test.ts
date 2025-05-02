import {
    CoreBuffer,
    CryptoDerivationHandle,
    CryptoEncryption,
    CryptoEncryptionAlgorithm,
    ProviderIdentifier
} from "@nmshd/crypto";
import { Cipher, KeySpec } from "@nmshd/rs-crypto-types";

export class CryptoDerivationHandleTest {
    public static run() {
        describe("CryptoDerivationHandle", function () {
            const providerIdent: ProviderIdentifier = { providerName: "SoftwareProvider" };

            it("deriveKeyFromBase", async function () {
                const ciphers: Cipher[] = ["AesGcm128", "AesGcm256", "XChaCha20Poly1305"];

                for (const cipher of ciphers) {
                    const spec: KeySpec = {
                        cipher,
                        signing_hash: "Sha2_512",
                        ephemeral: false
                    };
                    const keyHandle = await CryptoEncryption.generateKeyHandle(providerIdent, spec);
                    const rawKey = await keyHandle.keyHandle.extractKey();

                    const derivedKey = await CryptoDerivationHandle.deriveKeyFromBase(
                        providerIdent,
                        new CoreBuffer(rawKey),
                        1234,
                        "testTest",
                        CryptoEncryptionAlgorithm.fromCalCipher(cipher)
                    );
                }
            });
        });
    }
}
