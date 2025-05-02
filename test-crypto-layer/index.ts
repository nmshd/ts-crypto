import { initCryptoLayerProviders, SodiumWrapper } from "@nmshd/crypto";
import {
    createProvider,
    createProviderFromName,
    getAllProviders,
    getProviderCapabilities
} from "@nmshd/rs-crypto-node";
import chai from "chai";
import { CryptoDerivationHandleTest } from "./crypto-layer/CryptoDerivation.test";
import { CryptoExportedPublicKeyTest } from "./crypto-layer/CryptoExportedPublicKey.test";
import { CryptoLayerProviderTest } from "./crypto-layer/CryptoLayerProviderTest.test";
import { CryptoSecretKeyHandleTest } from "./crypto-layer/encryption/CryptoSecretKeyHandle.test";
import { CryptoExchangeTest } from "./crypto-layer/exchange/CryptoExchange.test";
import { CryptoExchangeKeypairHandleTest } from "./crypto-layer/exchange/CryptoExchangeKeypairHandle.test";
import { CryptoExchangePrivateKeyHandleTest } from "./crypto-layer/exchange/CryptoExchangePrivateKeyHandle.test";
import { CryptoExchangePublicKeyHandleTest } from "./crypto-layer/exchange/CryptoExchangePublicKeyHandle.test";
import { CryptoSignatureKeypairHandleTest } from "./crypto-layer/signature/CryptoSignatureKeypairHandle.test";
import { CryptoSignaturePrivateKeyHandleTest } from "./crypto-layer/signature/CryptoSignaturePrivateKeyHandle.test";
import { CryptoSignaturePublicKeyHandleTest } from "./crypto-layer/signature/CryptoSignaturePublicKeyHandle.test";

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
    CryptoExportedPublicKeyTest.run();

    // Signature
    CryptoSignatureKeypairHandleTest.run();
    CryptoSignaturePrivateKeyHandleTest.run();
    CryptoSignaturePublicKeyHandleTest.run();

    // Exchange
    CryptoExchangeTest.run();
    CryptoExchangePrivateKeyHandleTest.run();
    CryptoExchangePublicKeyHandleTest.run();
    CryptoExchangeKeypairHandleTest.run();

    // Encryption
    CryptoSecretKeyHandleTest.run();

    // Derivation
    CryptoDerivationHandleTest.run();

    run();
})();
