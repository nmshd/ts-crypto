import { CryptoEncryptionAlgorithm } from "@nmshd/crypto";
import { DHExchange, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { CryptoExchangeWithCryptoLayer, ProviderIdentifier } from "src/crypto-layer";
import { parameterizedKeyPairSpec } from "../CryptoLayerTestUtil";
import {
    assertAsymmetricKeyHandleEqual,
    assertAsymmetricKeyHandleValid,
    assertCryptoKeyPairHandleValid
} from "../KeyValidation";

export class CryptoExchangeTest {
    static run(): void {
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

            it("generateKeyPair()", async () => {
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

            parameterizedKeyPairSpec(
                "key exchange",
                async (spec: KeyPairSpec) => {
                    const dhHandleClient: DHExchange = await CryptoExchangeWithCryptoLayer.generateDHExchange(
                        providerIdent,
                        spec
                    );
                    const dhHandleServer: DHExchange = await CryptoExchangeWithCryptoLayer.generateDHExchange(
                        providerIdent,
                        spec
                    );

                    const clientPublicKeyBytes: Uint8Array = await dhHandleClient.getPublicKey();
                    const serverPublicKeyBytes: Uint8Array = await dhHandleServer.getPublicKey();

                    const clientKey = await CryptoExchangeWithCryptoLayer.deriveRequestor(
                        dhHandleClient,
                        serverPublicKeyBytes,
                        CryptoEncryptionAlgorithm.AES256_GCM
                    );
                    const serverKey = await CryptoExchangeWithCryptoLayer.deriveTemplator(
                        dhHandleServer,
                        clientPublicKeyBytes,
                        CryptoEncryptionAlgorithm.AES256_GCM
                    );

                    expect(clientKey.algorithm)
                        .to.equal(serverKey.algorithm)
                        .and.to.equal(CryptoEncryptionAlgorithm.AES256_GCM);

                    expect(clientKey.transmissionKey.toBase64URL()).to.deep.equal(serverKey.receivingKey.toBase64URL());
                    expect(clientKey.receivingKey.toBase64URL()).to.deep.equal(serverKey.transmissionKey.toBase64URL());
                },
                {
                    asymSpec: ["Curve25519", "P256"],
                    cipher: ["AesGcm256", null],
                    signingHash: ["Sha2_512"],
                    ephemeral: [false, true],
                    nonExportable: [false, true]
                }
            );
        });
    }
}
