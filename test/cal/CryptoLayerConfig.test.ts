import { SerializableBase } from "@js-soft/ts-serval";
import {
    CryptoEncryptionAlgorithm,
    CryptoEncryptionHandle,
    CryptoHashAlgorithm,
    CryptoLayerProviderToBeInitialized,
    DeviceBoundKeyHandle,
    DeviceBoundKeyPairHandle
} from "@nmshd/crypto";
import { isKeyHandle } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../index.node";

export class CryptoLayerConfigTest {
    public static run(): void {
        describe("CryptoLayerProviderToBeInitialized", function () {
            it("should serialize and deserialize empty", async function () {
                const config = CryptoLayerProviderToBeInitialized.new({ providerName: "TestProvider" });

                const blob = config.serialize();

                const deserialized = await CryptoLayerProviderToBeInitialized.deserialize(blob);

                expect(deserialized.providerName).to.exist.and.to.equal(config.providerName);
                expect(deserialized.masterEncryptionKeyHandle).to.be.undefined;
                expect(deserialized.masterSignatureKeyHandle).to.be.undefined;
                expect(deserialized.dependentProvider).to.be.undefined;
            });

            it("should serialize and deserialize with handles", async function () {
                SerializableBase.addModule(DeviceBoundKeyHandle);
                SerializableBase.addModule(DeviceBoundKeyPairHandle);

                const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                    TEST_PROVIDER_IDENT,
                    CryptoEncryptionAlgorithm.AES256_GCM,
                    CryptoHashAlgorithm.SHA256
                );

                const config = CryptoLayerProviderToBeInitialized.new({
                    providerName: "TestProvider",
                    masterEncryptionKeyHandle: keyHandle
                });

                const blob = config.serialize();

                const deserialized = await CryptoLayerProviderToBeInitialized.deserialize(blob);

                expect(deserialized.providerName).to.exist.and.to.equal(config.providerName);
                expect(deserialized.masterSignatureKeyHandle).to.be.undefined;
                expect(deserialized.dependentProvider).to.be.undefined;

                expect(deserialized.masterEncryptionKeyHandle).to.exist.and.to.be.instanceOf(DeviceBoundKeyHandle);
                if (!(deserialized.masterEncryptionKeyHandle instanceof DeviceBoundKeyHandle)) {
                    throw new Error("Failed to deserialize key handle of provider to be initialized.");
                }

                expect(deserialized.masterEncryptionKeyHandle.id).to.exist.and.to.equal(keyHandle.id);

                /* deserialized.masterEncryptionKeyHandle = await DeviceBoundKeyHandle.postFrom(
                    deserialized.masterEncryptionKeyHandle
                ); */

                expect(deserialized.masterEncryptionKeyHandle.keyHandle).to.exist.and.to.satisfy(isKeyHandle);
                // expect(await deserialized.masterEncryptionKeyHandle.keyHandle.id()).to.exist.and.to.equal(keyHandle.id);
            });

            it("should serialize and deserialize with dependentProvider", async function () {
                const dependantConfig = CryptoLayerProviderToBeInitialized.new({
                    providerName: "TestProviderDependent"
                });

                const config = CryptoLayerProviderToBeInitialized.new({
                    providerName: "TestProvider",
                    dependentProvider: dependantConfig
                });

                const blob = config.serialize();

                const deserialized = await CryptoLayerProviderToBeInitialized.deserialize(blob);

                expect(deserialized.providerName).to.exist.and.to.equal(config.providerName);
                expect(deserialized.masterEncryptionKeyHandle).to.be.undefined;
                expect(deserialized.masterSignatureKeyHandle).to.be.undefined;
                expect(deserialized.dependentProvider?.providerName).to.exist.and.to.equal(
                    dependantConfig.providerName
                );
            });
        });
    }
}
