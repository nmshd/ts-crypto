import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CryptoExchangeWithCryptoLayer, ProviderIdentifier } from "src/crypto-layer";
import {
    assertAsymmetricKeyHandleEqual,
    assertAsymmetricKeyHandleValid,
    assertCryptoKeyPairHandleValid
} from "../KeyValidation";

export class CryptoExchangeTest {
    run(): void {
        describe("CryptoExchangeWithCryptoLayer", () => {
            const spec: KeyPairSpec = {
                asym_spec: "P256",
                cipher: null,
                signing_hash: "Sha2_512",
                ephemeral: false,
                non_exportable: false
            };
            const providerIdent: ProviderIdentifier = {
                providerName: "SoftwareProvider"
            };

            it("generateKeypair()", async () => {
                const keyPairHandle = await CryptoExchangeWithCryptoLayer.generateKeypair(providerIdent, spec);
                await assertCryptoKeyPairHandleValid(keyPairHandle);
            });

            it("privateKeyToPublicKey()", async () => {
                const keyPairHandle = await CryptoExchangeWithCryptoLayer.generateKeypair(providerIdent, spec);
                await assertCryptoKeyPairHandleValid(keyPairHandle);
                const newPublicKey = await CryptoExchangeWithCryptoLayer.privateKeyToPublicKey(
                    keyPairHandle.privateKey
                );
                await assertAsymmetricKeyHandleValid(newPublicKey);
                await assertAsymmetricKeyHandleEqual(keyPairHandle.publicKey, newPublicKey);
            });
        });
    }
}
