import { initCryptoLayerProviders, SodiumWrapper } from "@nmshd/crypto";
import {
    createProvider,
    createProviderFromName,
    getAllProviders,
    getProviderCapabilities
} from "@nmshd/rs-crypto-node";
import chai from "chai";
import { CryptoDerivationHandleTest } from "./crypto-layer/CryptoDerivation.test";
import { CryptoLayerProviderTest } from "./crypto-layer/CryptoLayerProviderTest.test";
import { CryptoSecretKeyHandleTest } from "./crypto-layer/encryption/CryptoSecretKeyHandle.test";

chai.config.truncateThreshold = 0;

(async function () {
    await Promise.all([
        initCryptoLayerProviders({
            factoryFunctions: { getAllProviders, createProvider, createProviderFromName, getProviderCapabilities },
            keyMetadataStoreConfig: { FileStoreConfig: { db_dir: "./test_cal_db" } },
            keyMetadataStoreAuth: { StorageConfigPass: "12345678" },
            providersToBeInitialized: [{ providerName: "SoftwareProvider" }]
        }),
        SodiumWrapper.ready()
    ]);
    CryptoLayerProviderTest.run();

    // Encryption
    CryptoSecretKeyHandleTest.run();

    // Derivation
    CryptoDerivationHandleTest.run();

    run();
})();
