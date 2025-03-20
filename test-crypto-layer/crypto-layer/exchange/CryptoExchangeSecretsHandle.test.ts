import { CryptoExchangeSecretsHandle, CryptoExchangeWithCryptoLayer } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { assertCryptoAsymmetricKeyHandle } from "../CryptoAsymmetricKeyHandle";

function assertCryptoExchangeSecretsHandle(value: CryptoExchangeSecretsHandle): void {
    // TODO
}

// TODO Does testing this have a meaning?
export class CryptoExchangeSecretsHandleTest {
    static async run() {
        const providerIdent = "SoftwareProvider";
        const spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_512",
            ephemeral: false,
            non_exportable: false
        };

        const exchangeKeyPairHandle = await CryptoExchangeWithCryptoLayer.generateKeypair(
            { providerName: providerIdent },
            spec
        );
        assertCryptoAsymmetricKeyHandle(exchangeKeyPairHandle.privateKey);
        assertCryptoAsymmetricKeyHandle(exchangeKeyPairHandle.publicKey);

        const foreignPublicKeyHandle = (
            await CryptoExchangeWithCryptoLayer.generateKeypair({ providerName: providerIdent }, spec)
        ).publicKey;
        assertCryptoAsymmetricKeyHandle(foreignPublicKeyHandle);

        /* describe("CryptoExchangeSecretsHandle", () => {
            TestSerializeDeserializeOfBase64AndJson(
                "CryptoExchangeSecretsHandle",
                async () => {
                    return await CryptoExchange.deriveRequestor(exchangeKeyPairHandle, foreignPublicKeyHandle);
                },
                CryptoExchangeSecretsHandle,
                assertCryptoExchangeSecretsHandle,
                (before: CryptoExchangeSecretsHandle, after: CryptoExchangeSecretsHandle) => {
                    expect(before.algorithm).to.equal(after.algorithm);
                    expect(before.transmissionKey.secretKey.buffer).to.equal(after.transmissionKey.secretKey.buffer);
                    expect(before.receivingKey.secretKey.buffer).to.equal(after.receivingKey.secretKey.buffer);
                }
            );
        }); */
    }
}
