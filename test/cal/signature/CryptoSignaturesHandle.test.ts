import { assertKeyPairHandle } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";

import {
    CoreBuffer,
    CryptoEncryptionAlgorithm,
    CryptoHashAlgorithm,
    CryptoSignatureAlgorithm,
    CryptoSignaturesHandle,
    DeviceBoundKeyPairHandle
} from "@nmshd/crypto";
import { TEST_PROVIDER_IDENT } from "../../index.node";

export class CryptoSignaturesHandleTest {
    public static run(): void {
        describe("CryptoSignaturesHandle", function () {
            describe("Key Pair Creation", function () {
                it("should generate device bound key pair handle", async function () {
                    const keyPair = await CryptoSignaturesHandle.generateDeviceBoundKeyPairHandle(
                        TEST_PROVIDER_IDENT,
                        CryptoSignatureAlgorithm.ECDSA_P256,
                        CryptoEncryptionAlgorithm.AES256_GCM,
                        CryptoHashAlgorithm.SHA256
                    );

                    assertKeyPairHandle(keyPair.keyPairHandle);
                    expect(await keyPair.keyPairHandle.id()).to.be.a("string");
                });

                it("should load correct key pair from id and verify signature", async function () {
                    const data = CoreBuffer.fromUtf8("some data that should be signed");

                    let serializedKeyPair: string;
                    let signature: Uint8Array;

                    {
                        const keyPair = await CryptoSignaturesHandle.generateDeviceBoundKeyPairHandle(
                            TEST_PROVIDER_IDENT,
                            CryptoSignatureAlgorithm.ECDSA_P256,
                            CryptoEncryptionAlgorithm.AES256_GCM,
                            CryptoHashAlgorithm.SHA256
                        );

                        assertKeyPairHandle(keyPair.keyPairHandle);

                        signature = await keyPair.keyPairHandle.signData(data.buffer);
                        expect(signature).to.exist;

                        serializedKeyPair = keyPair.serialize();
                        expect(serializedKeyPair).to.be.a("string");
                    }
                    {
                        const keyPair = await DeviceBoundKeyPairHandle.deserialize(serializedKeyPair);
                        assertKeyPairHandle(keyPair.keyPairHandle);

                        expect(await keyPair.keyPairHandle.verifySignature(data.buffer, signature)).to.be.true;
                    }
                });
            });
        });
    }
}
