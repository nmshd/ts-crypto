import { initCryptoLayerProviders, ProviderIdentifier, SodiumWrapper } from "@nmshd/crypto";
import {
    createProvider,
    createProviderFromName,
    getAllProviders,
    getProviderCapabilities
} from "@nmshd/rs-crypto-node";
import chai from "chai";
import { CryptoDerivationHandleTest } from "./crypto-layer/CryptoDerivation.test";
import { CryptoLayerProviderTest } from "./crypto-layer/CryptoLayerProviderTest.test";
import { CryptoEncryptionHandleTest } from "./crypto-layer/encryption/CryptoEncryptionHandle.test";
import { CryptoSecretKeyHandleTest } from "./crypto-layer/encryption/CryptoSecretKeyHandle.test";

chai.config.truncateThreshold = 0;

export const TEST_PROVIDER_IDENT: ProviderIdentifier = { providerName: "SoftwareProvider" };

// eslint-disable-next-line @typescript-eslint/no-floating-promises
(async function () {
    await Promise.all([
        initCryptoLayerProviders({
            factoryFunctions: { getAllProviders, createProvider, createProviderFromName, getProviderCapabilities },
            // eslint-disable-next-line @typescript-eslint/naming-convention
            keyMetadataStoreConfig: { FileStoreConfig: { db_dir: "./test_cal_db" } },
            // eslint-disable-next-line @typescript-eslint/naming-convention
            keyMetadataStoreAuth: { StorageConfigPass: "12345678" },
            providersToBeInitialized: [TEST_PROVIDER_IDENT]
        }),
        SodiumWrapper.ready()
    ]);

    CryptoLayerProviderTest.run();

    // Encryption
    CryptoSecretKeyHandleTest.run();
    CryptoEncryptionHandleTest.run();

    // Derivation
    CryptoDerivationHandleTest.run();

    run();
})();
