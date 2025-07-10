import {
    CryptoEncryptionAlgorithm,
    CryptoEncryptionHandle,
    CryptoHashAlgorithm,
    ProviderInitConfig,
    ProviderInitConfigKeyHandle
} from "@nmshd/crypto";
import { assertKeyHandle, isKeyHandle } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../index.node";

export class CryptoLayerConfigTest {
    public static run(): void {
        describe("ProviderInitConfig", function () {
            it("should serialize and deserialize empty", function () {
                const config = ProviderInitConfig.from({ providerName: "TestProvider" });

                const blob = config.serialize();

                const deserialized = ProviderInitConfig.deserialize(blob);

                expect(deserialized.providerName).to.exist.and.to.equal(config.providerName);
                expect(deserialized.masterEncryptionKeyHandle).to.be.undefined;
                expect(deserialized.masterSignatureKeyHandle).to.be.undefined;
                expect(deserialized.dependentProvider).to.be.undefined;
            });

            it("should serialize and deserialize with handles", async function () {
                /* SerializableBase.addModule(DeviceBoundKeyHandle);
                SerializableBase.addModule(DeviceBoundKeyPairHandle); */

                const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                    TEST_PROVIDER_IDENT,
                    CryptoEncryptionAlgorithm.AES256_GCM,
                    CryptoHashAlgorithm.SHA256
                );

                const config = ProviderInitConfig.from({
                    providerName: "TestProvider",
                    masterEncryptionKeyHandle: ProviderInitConfigKeyHandle.encode(keyHandle)
                });

                const blob = config.serialize();

                const deserialized = ProviderInitConfig.deserialize(blob);

                expect(deserialized.providerName).to.exist.and.to.equal(config.providerName);
                expect(deserialized.masterSignatureKeyHandle).to.be.undefined;
                expect(deserialized.dependentProvider).to.be.undefined;

                expect(deserialized.masterEncryptionKeyHandle).to.exist.and.to.be.instanceOf(
                    ProviderInitConfigKeyHandle
                );
                if (!(deserialized.masterEncryptionKeyHandle instanceof ProviderInitConfigKeyHandle)) {
                    throw new Error("Failed to deserialize key handle of provider to be initialized.");
                }

                expect(deserialized.masterEncryptionKeyHandle.keyId).to.exist.and.to.equal(keyHandle.id);

                const loadedEncryptionKeyHandle = await deserialized.masterEncryptionKeyHandle.load();

                expect(loadedEncryptionKeyHandle).to.exist.and.to.satisfy(isKeyHandle);
                expect(await loadedEncryptionKeyHandle.id()).to.exist.and.to.equal(keyHandle.id);
            });

            it("should serialize and deserialize with dependentProvider", function () {
                const dependantConfig = ProviderInitConfig.from({
                    providerName: "TestProviderDependent"
                });

                const config = ProviderInitConfig.from({
                    providerName: "TestProvider",
                    dependentProvider: dependantConfig
                });

                const blob = config.serialize();

                const deserialized = ProviderInitConfig.deserialize(blob);

                expect(deserialized.providerName).to.exist.and.to.equal(config.providerName);
                expect(deserialized.masterEncryptionKeyHandle).to.be.undefined;
                expect(deserialized.masterSignatureKeyHandle).to.be.undefined;
                expect(deserialized.dependentProvider?.providerName).to.exist.and.to.equal(
                    dependantConfig.providerName
                );
            });
        });

        describe("ProviderInitConfigKeyHandle", function () {
            it("should be constructable", function () {
                const configKeyHandle = ProviderInitConfigKeyHandle.from({
                    keyId: "key1234",
                    providerName: "provider1234",
                    type: "symmetric"
                });

                expect(configKeyHandle).to.exist.and.to.be.instanceOf(ProviderInitConfigKeyHandle);
                expect(configKeyHandle.type).to.equal("symmetric");
                expect(configKeyHandle.keyId).to.equal("key1234");
                expect(configKeyHandle.providerName).to.equal("provider1234");
            });

            it("should be constructable from DeviceBoundKeyHandle", async function () {
                const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                    TEST_PROVIDER_IDENT,
                    CryptoEncryptionAlgorithm.AES256_GCM,
                    CryptoHashAlgorithm.SHA256
                );

                const configKeyHandle = ProviderInitConfigKeyHandle.encode(keyHandle);

                expect(configKeyHandle).to.exist.and.to.be.instanceOf(ProviderInitConfigKeyHandle);
                expect(configKeyHandle.type).to.equal("symmetric");
                expect(configKeyHandle.keyId).to.equal(keyHandle.id);
                expect(configKeyHandle.providerName).to.equal(keyHandle.providerName);
            });

            it("should load key handle", async function () {
                const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                    TEST_PROVIDER_IDENT,
                    CryptoEncryptionAlgorithm.AES256_GCM,
                    CryptoHashAlgorithm.SHA256
                );

                const configKeyHandle = ProviderInitConfigKeyHandle.encode(keyHandle);

                const loadedKeyHandle = await configKeyHandle.load();

                assertKeyHandle(loadedKeyHandle);

                expect(await loadedKeyHandle.id()).to.equal(keyHandle.id);
            });
        });
    }
}
