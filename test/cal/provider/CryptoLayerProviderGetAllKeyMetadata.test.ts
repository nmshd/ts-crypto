import { expect } from "chai";

import {
    CryptoEncryptionAlgorithm,
    CryptoEncryptionHandle,
    CryptoHashAlgorithm,
    keyCountOfProvider,
    keysOfProvider
} from "@nmshd/crypto";

import { TEST_PROVIDER_IDENT } from "../../index.node";

export class CryptoLayerProviderGetAllKeyMetadata {
    public static run(): void {
        describe("CryptoLayerProviderGetAllKeyMetadata", function () {
            it("test provider should store keys", async function () {
                expect(await keyCountOfProvider(TEST_PROVIDER_IDENT)).to.be.greaterThan(0);
            });

            it("keysOfProvider should include a created key", async function () {
                const encryptionAlgorithm = CryptoEncryptionAlgorithm.AES256_GCM;
                const hashAlgorithm = CryptoHashAlgorithm.SHA256;

                const keyHandle = await CryptoEncryptionHandle.generatePortableKeyHandle(
                    TEST_PROVIDER_IDENT,
                    encryptionAlgorithm,
                    hashAlgorithm
                );

                const keyMetadataArray = await keysOfProvider(TEST_PROVIDER_IDENT);
                expect(keyMetadataArray).to.exist.and.to.satisfy(Array.isArray);
                expect(keyMetadataArray.length).to.be.greaterThanOrEqual(1);

                const metadata = keyMetadataArray.find((metadata) => metadata.id === keyHandle.id);
                expect(metadata).to.exist;

                if (metadata === undefined) {
                    throw new Error("keysOfProvider did not return metadata of key handle known to exist.");
                }

                expect(metadata.id).to.equal(keyHandle.id);
                expect(metadata.type).to.equal("symmetric");
                expect(metadata.deviceBound).to.be.false;
                expect(metadata.ephemeral).to.be.false;
                expect(metadata.encryptionAlgorithm).to.equal(encryptionAlgorithm);
                expect(metadata.hashAlgorithm).to.equal(hashAlgorithm);
            });
        });
    }
}
