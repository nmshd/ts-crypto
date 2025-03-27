import { CryptoExchangePrivateKeyHandle, CryptoExchangeWithCryptoLayer } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { TestSerializeDeserializeOfAsymmetricKeyPairHandle } from "../CommonSerialize";

export class CryptoExchangePrivateKeyHandleTest {
    static run() {
        const providerIdent = "SoftwareProvider";
        const spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_512",
            ephemeral: false,
            non_exportable: false
        };

        describe("CryptoExchangePrivateKeyHandle", () => {
            TestSerializeDeserializeOfAsymmetricKeyPairHandle(
                "CryptoExchangePrivateKeyHandle",
                async () => {
                    return (await CryptoExchangeWithCryptoLayer.generateKeypair({ providerName: providerIdent }, spec))
                        .privateKey;
                },
                CryptoExchangePrivateKeyHandle
            );
        });
    }
}
