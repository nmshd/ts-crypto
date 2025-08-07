import { anything, capture, instance, mock, resetCalls, verify, when } from "@typestrong/ts-mockito";

import {
    clearProviders,
    CryptoEncryptionAlgorithm,
    CryptoErrorCode,
    CryptoHashAlgorithm,
    getProvider,
    hasProviderForSecurityLevel,
    initializeProviders,
    newInitializedProviders,
    ProviderInitConfig,
    providersInitialized,
    StorageConfig
} from "@nmshd/crypto";
import {
    KeyHandle,
    KeyPairHandle,
    KeySpec,
    Provider,
    ProviderConfig,
    ProviderFactoryFunctions
} from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { expectThrows } from "../CryptoLayerTestUtil";

const mockKeyId = "mockKey12345678";
const mockKeyPairId = "mockKeyPair12345678";

const mockedKeyHandle: KeyHandle = mock<KeyHandle>();
when(mockedKeyHandle.id()).thenResolve(mockKeyId);

const mockedKeyPairHandle: KeyPairHandle = mock<KeyPairHandle>();
when(mockedKeyPairHandle.id()).thenResolve(mockKeyPairId);

const mockedSoftwareProviderCaps: ProviderConfig = mock<ProviderConfig>();
when(mockedSoftwareProviderCaps.min_security_level).thenReturn("Software");
when(mockedSoftwareProviderCaps.max_security_level).thenReturn("Software");

const mockedSoftwareProvider: Provider = mock<Provider>();
when(mockedSoftwareProvider.providerName()).thenResolve("SoftwareProvider");
when(mockedSoftwareProvider.createKey(anything())).thenResolve(instance(mockedKeyHandle));
when(mockedSoftwareProvider.loadKey(anything())).thenResolve(instance(mockedKeyHandle));
when(mockedSoftwareProvider.getCapabilities()).thenResolve(instance(mockedSoftwareProviderCaps));

const mockedAndroidProviderCaps: ProviderConfig = mock<ProviderConfig>();
when(mockedAndroidProviderCaps.min_security_level).thenReturn("Hardware");
when(mockedAndroidProviderCaps.max_security_level).thenReturn("Hardware");

const mockedAndroidProvider: Provider = mock<Provider>();
when(mockedAndroidProvider.providerName()).thenResolve("ANDROID_PROVIDER_SECURE_ELEMENT");
when(mockedAndroidProvider.createKey(anything())).thenResolve(instance(mockedKeyHandle));
when(mockedAndroidProvider.loadKey(anything())).thenResolve(instance(mockedKeyHandle));
when(mockedAndroidProvider.createKeyPair(anything())).thenResolve(instance(mockedKeyPairHandle));
when(mockedAndroidProvider.loadKeyPair(anything())).thenResolve(instance(mockedKeyPairHandle));
when(mockedAndroidProvider.getCapabilities()).thenResolve(instance(mockedAndroidProviderCaps));

// The real android provider (ANDROID_PROVIDER) is in fact a hardware provider.
const mockedAndroidSoftwareProviderCaps: ProviderConfig = mock<ProviderConfig>();
when(mockedAndroidSoftwareProviderCaps.min_security_level).thenReturn("Software");
when(mockedAndroidSoftwareProviderCaps.max_security_level).thenReturn("Software");

const mockedAndroidSoftwareProvider: Provider = mock<Provider>();
when(mockedAndroidSoftwareProvider.providerName()).thenResolve("ANDROID_PROVIDER");
when(mockedAndroidSoftwareProvider.createKey(anything())).thenResolve(instance(mockedKeyHandle));
when(mockedAndroidSoftwareProvider.createKeyPair(anything())).thenResolve(instance(mockedKeyPairHandle));
when(mockedAndroidSoftwareProvider.getCapabilities()).thenResolve(instance(mockedAndroidSoftwareProviderCaps));

const mockedImaginaryProviderCaps: ProviderConfig = mock<ProviderConfig>();
when(mockedImaginaryProviderCaps.min_security_level).thenReturn("Hardware");
when(mockedImaginaryProviderCaps.max_security_level).thenReturn("Hardware");

const mockedImaginaryProvider: Provider = mock<Provider>();
when(mockedImaginaryProvider.providerName()).thenResolve("IMAGINARY_PROVIDER");
when(mockedImaginaryProvider.createKey(anything())).thenResolve(instance(mockedKeyHandle));
when(mockedImaginaryProvider.loadKey(anything())).thenResolve(instance(mockedKeyHandle));
when(mockedImaginaryProvider.createKeyPair(anything())).thenResolve(instance(mockedKeyPairHandle));
when(mockedImaginaryProvider.loadKeyPair(anything())).thenResolve(instance(mockedKeyPairHandle));
when(mockedImaginaryProvider.getCapabilities()).thenResolve(instance(mockedImaginaryProviderCaps));

const mockedStorageConfig: StorageConfig = mock<StorageConfig>();

export class CryptoLayerProvidersTest {
    public static run(): void {
        describe("CryptoLayerProviders", function () {
            beforeEach(function () {
                clearProviders();
                resetCalls(mockedKeyHandle);
                resetCalls(mockedSoftwareProvider, mockedAndroidProvider, mockedImaginaryProvider);
            });

            it("should create software provider", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                expect(loadConfig).to.exist.and.to.be.instanceOf(ProviderInitConfig);
                expect(loadConfig?.providerName).to.equal("SoftwareProvider");
                expect(loadConfig?.masterEncryptionKeyHandle).to.be.undefined;
                expect(loadConfig?.masterSignatureKeyHandle).to.be.undefined;
                expect(loadConfig?.requiredProvider).to.be.undefined;

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(await getProvider({ providerName: "SoftwareProvider" }).providerName()).to.equal(
                    "SoftwareProvider"
                );
                expect(() => getProvider({ securityLevel: "Hardware" })).to.throw(
                    CryptoErrorCode.CalThisProviderNotInitialized
                );
                expect(providersInitialized()).to.be.true;
                expect(hasProviderForSecurityLevel("Software")).to.be.true;
                expect(hasProviderForSecurityLevel("Hardware")).to.be.false;
            });

            it("should return undefined if neither software nor hardware providers are available", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([]);

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                expect(loadConfig).to.be.undefined;

                expect(providersInitialized()).to.be.false;
            });

            it("should ignore hardware providers without storage security config", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)],
                    ["IMAGINARY_PROVIDER", instance(mockedImaginaryProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                expect(loadConfig).to.exist.and.to.be.instanceOf(ProviderInitConfig);
                expect(loadConfig?.providerName).to.equal("SoftwareProvider");
                expect(loadConfig?.masterEncryptionKeyHandle).to.be.undefined;
                expect(loadConfig?.masterSignatureKeyHandle).to.be.undefined;
                expect(loadConfig?.requiredProvider).to.be.undefined;

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(hasProviderForSecurityLevel("Hardware")).to.be.false;
            });

            it("should create a software provider secured by an android provider", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)],
                    ["ANDROID_PROVIDER_SECURE_ELEMENT", instance(mockedAndroidProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );
                when(mockedFactory.createProviderFromName("ANDROID_PROVIDER_SECURE_ELEMENT", anything())).thenResolve(
                    instance(mockedAndroidProvider)
                );

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                expect(loadConfig).to.exist.and.to.be.instanceOf(ProviderInitConfig);
                expect(loadConfig?.providerName).to.equal("SoftwareProvider");
                expect(loadConfig?.masterEncryptionKeyHandle?.keyId).to.equal(mockKeyId);
                expect(loadConfig?.masterSignatureKeyHandle?.keyId).to.equal(mockKeyPairId);
                expect(loadConfig?.requiredProvider?.providerName).to.equal("ANDROID_PROVIDER_SECURE_ELEMENT");
                expect(loadConfig?.requiredProvider?.masterEncryptionKeyHandle).to.be.undefined;
                expect(loadConfig?.requiredProvider?.masterSignatureKeyHandle).to.be.undefined;
                expect(loadConfig?.requiredProvider?.requiredProvider).to.be.undefined;

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(await getProvider({ securityLevel: "Hardware" }).providerName()).to.equal(
                    "ANDROID_PROVIDER_SECURE_ELEMENT"
                );
            });

            it("should use supplied storage security config", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)],
                    ["IMAGINARY_PROVIDER", instance(mockedImaginaryProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );
                when(mockedFactory.createProviderFromName("IMAGINARY_PROVIDER", anything())).thenResolve(
                    instance(mockedImaginaryProvider)
                );

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory),
                    [
                        {
                            name: "IMAGINARY_PROVIDER",
                            signature: {
                                type: "symmetric",
                                encryptionAlgorithm: CryptoEncryptionAlgorithm.AES256_GCM,
                                hashingAlgorithm: CryptoHashAlgorithm.SHA256
                            },
                            encryption: {
                                type: "symmetric",
                                encryptionAlgorithm: CryptoEncryptionAlgorithm.AES256_GCM,
                                hashingAlgorithm: CryptoHashAlgorithm.SHA256
                            }
                        }
                    ]
                );

                expect(loadConfig).to.exist.and.to.be.instanceOf(ProviderInitConfig);
                expect(loadConfig?.providerName).to.equal("SoftwareProvider");
                expect(loadConfig?.masterEncryptionKeyHandle?.keyId).to.equal(mockKeyId);
                expect(loadConfig?.masterSignatureKeyHandle?.keyId).to.equal(mockKeyId);
                expect(loadConfig?.requiredProvider?.providerName).to.equal("IMAGINARY_PROVIDER");

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(await getProvider({ securityLevel: "Hardware" }).providerName()).to.equal("IMAGINARY_PROVIDER");

                verify(mockedImaginaryProvider.createKey(anything())).twice();
                const [keySpec1] = capture(mockedImaginaryProvider.createKey).last();
                const [keySpec2] = capture(mockedImaginaryProvider.createKey).beforeLast();

                const checkKeySpec = (spec: KeySpec) =>
                    expect(spec).to.deep.equal({
                        cipher: "AesGcm256",
                        ephemeral: false,
                        // eslint-disable-next-line @typescript-eslint/naming-convention
                        non_exportable: true,
                        // eslint-disable-next-line @typescript-eslint/naming-convention
                        signing_hash: "Sha2_256"
                    } as KeySpec);

                checkKeySpec(keySpec1);
                checkKeySpec(keySpec2);

                const [hardwareProviderName, implConfigHardware] = capture(
                    mockedFactory.createProviderFromName
                ).beforeLast();
                expect(hardwareProviderName).to.equal("IMAGINARY_PROVIDER");
                expect(implConfigHardware.additional_config).to.be.of.length(1);
                const [softwareProviderName, implConfigSoftware] = capture(mockedFactory.createProviderFromName).last();
                expect(softwareProviderName).to.equal("SoftwareProvider");
                expect(implConfigSoftware.additional_config).to.be.of.length(3);
                expect(implConfigSoftware.additional_config).to.deep.include({
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    StorageConfigHMAC: instance(mockedKeyHandle)
                });
                expect(implConfigSoftware.additional_config).to.deep.include({
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    StorageConfigSymmetricEncryption: instance(mockedKeyHandle)
                });
            });

            it("should prefer android software provider over fallback software provider", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)],
                    ["ANDROID_PROVIDER", instance(mockedAndroidSoftwareProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );
                when(mockedFactory.createProviderFromName("ANDROID_PROVIDER", anything())).thenResolve(
                    instance(mockedAndroidSoftwareProvider)
                );

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                expect(loadConfig).to.exist.and.to.be.instanceOf(ProviderInitConfig);
                expect(loadConfig?.providerName).to.equal("ANDROID_PROVIDER");
                expect(loadConfig?.masterEncryptionKeyHandle).to.be.undefined;
                expect(loadConfig?.masterSignatureKeyHandle).to.be.undefined;
                expect(loadConfig?.requiredProvider).to.be.undefined;

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("ANDROID_PROVIDER");
                expect(hasProviderForSecurityLevel("Hardware")).to.be.false;
            });

            it("should throw trying multiple initializations", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );

                const _loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                await expectThrows(
                    newInitializedProviders(instance(mockedStorageConfig), instance(mockedFactory)),
                    CryptoErrorCode.CalProvidersAlreadyInitialized
                );

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(hasProviderForSecurityLevel("Hardware")).to.be.false;
            });

            it("should load software provider from config", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(hasProviderForSecurityLevel("Hardware")).to.be.false;
                expect(providersInitialized()).to.be.true;

                clearProviders();
                expect(providersInitialized()).to.be.false;

                await initializeProviders(loadConfig!, instance(mockedStorageConfig), instance(mockedFactory));

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(hasProviderForSecurityLevel("Hardware")).to.be.false;
                expect(providersInitialized()).to.be.true;

                verify(mockedFactory.getProviderCapabilities(anything())).once();
                verify(mockedFactory.createProviderFromName(anything(), anything())).twice();
            });

            it("should load a software provider secured by an android provider with the correct keys", async function () {
                const mockedFactory: ProviderFactoryFunctions = mock<ProviderFactoryFunctions>();
                when(mockedFactory.getProviderCapabilities(anything())).thenResolve([
                    ["SoftwareProvider", instance(mockedSoftwareProviderCaps)],
                    ["ANDROID_PROVIDER_SECURE_ELEMENT", instance(mockedAndroidProviderCaps)]
                ]);
                when(mockedFactory.createProviderFromName("SoftwareProvider", anything())).thenResolve(
                    instance(mockedSoftwareProvider)
                );
                when(mockedFactory.createProviderFromName("ANDROID_PROVIDER_SECURE_ELEMENT", anything())).thenResolve(
                    instance(mockedAndroidProvider)
                );

                const loadConfig = await newInitializedProviders(
                    instance(mockedStorageConfig),
                    instance(mockedFactory)
                );

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(await getProvider({ securityLevel: "Hardware" }).providerName()).to.equal(
                    "ANDROID_PROVIDER_SECURE_ELEMENT"
                );
                expect(providersInitialized()).to.be.true;

                clearProviders();
                expect(providersInitialized()).to.be.false;

                await initializeProviders(loadConfig!, instance(mockedStorageConfig), instance(mockedFactory));

                expect(await getProvider({ securityLevel: "Software" }).providerName()).to.equal("SoftwareProvider");
                expect(await getProvider({ securityLevel: "Hardware" }).providerName()).to.equal(
                    "ANDROID_PROVIDER_SECURE_ELEMENT"
                );
                expect(providersInitialized()).to.be.true;

                const [hardwareProviderName, implConfigHardware] = capture(
                    mockedFactory.createProviderFromName
                ).beforeLast();
                expect(hardwareProviderName).to.equal("ANDROID_PROVIDER_SECURE_ELEMENT");
                expect(implConfigHardware.additional_config).to.be.of.length(1);
                const [softwareProviderName, implConfigSoftware] = capture(mockedFactory.createProviderFromName).last();
                expect(softwareProviderName).to.equal("SoftwareProvider");
                expect(implConfigSoftware.additional_config).to.be.of.length(3);
                expect(implConfigSoftware.additional_config).to.deep.include({
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    StorageConfigDSA: instance(mockedKeyPairHandle)
                });
                expect(implConfigSoftware.additional_config).to.deep.include({
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    StorageConfigSymmetricEncryption: instance(mockedKeyHandle)
                });
            });
        });
    }
}
