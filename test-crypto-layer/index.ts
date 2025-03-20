import { initCryptoLayerProviders, SodiumWrapper } from "@nmshd/crypto";
import {
    createProvider,
    createProviderFromName,
    getAllProviders,
    getProviderCapabilities
} from "@nmshd/rs-crypto-node";
import chai from "chai";
import { CryptoExportedPublicKeyTest } from "./crypto-layer/CryptoExportedPublicKey.test";
import { CryptoLayerProviderTest } from "./crypto-layer/CryptoLayerProviderTest.test";
import { CryptoExchangeKeypairHandleTest } from "./crypto-layer/exchange/CryptoExchangeKeypairHandle.test";
import { CryptoExchangePrivateKeyHandleTest } from "./crypto-layer/exchange/CryptoExchangePrivateKeyHandle.test";
import { CryptoExchangePublicKeyHandleTest } from "./crypto-layer/exchange/CryptoExchangePublicKeyHandle.test";
import { CryptoExchangeSecretsHandleTest } from "./crypto-layer/exchange/CryptoExchangeSecretsHandle.test";
import { CryptoSignatureKeypairHandleTest } from "./crypto-layer/signature/CryptoSignatureKeypairHandle.test";
import { CryptoSignaturePrivateKeyHandleTest } from "./crypto-layer/signature/CryptoSignaturePrivateKeyHandle.test";
import { CryptoSignaturePublicKeyHandleTest } from "./crypto-layer/signature/CryptoSignaturePublicKeyHandle.test";

chai.config.truncateThreshold = 0;

// This is valid: https://mochajs.org/#delayed-root-suite
// eslint-disable-next-line @typescript-eslint/no-floating-promises
(async function () {
    await Promise.all([
        initCryptoLayerProviders({
            factoryFunctions: { getAllProviders, createProvider, createProviderFromName, getProviderCapabilities },
            // eslint-disable-next-line @typescript-eslint/naming-convention
            keyMetadataStoreConfig: { FileStoreConfig: { db_dir: "./test_cal_db" } },
            // eslint-disable-next-line @typescript-eslint/naming-convention
            keyMetadataStoreAuth: { StorageConfigPass: "12345678" },
            providersToBeInitialized: [{ providerName: "SoftwareProvider" }]
        }),
        SodiumWrapper.ready()
    ]);
    CryptoLayerProviderTest.run();
    CryptoExportedPublicKeyTest.run();

    // Signature
    CryptoSignatureKeypairHandleTest.run();
    CryptoSignaturePrivateKeyHandleTest.run();
    CryptoSignaturePublicKeyHandleTest.run();

    // Exchange
    CryptoExchangePrivateKeyHandleTest.run();
    CryptoExchangePublicKeyHandleTest.run();
    await CryptoExchangeSecretsHandleTest.run();
    CryptoExchangeKeypairHandleTest.run();

    run();
})();
