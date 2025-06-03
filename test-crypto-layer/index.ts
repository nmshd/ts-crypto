import { initCryptoLayerProviders, ProviderIdentifier, SodiumWrapper } from "@nmshd/crypto";
import {
    createProvider,
    createProviderFromName,
    getAllProviders,
    getProviderCapabilities
} from "@nmshd/rs-crypto-node";
import { CryptoDerivationHandleTest } from "./crypto-layer/CryptoDerivation.test";
import { CryptoLayerProviderTest } from "./crypto-layer/CryptoLayerProviderTest.test";
import { CryptoEncryptionHandleTest } from "./crypto-layer/encryption/CryptoEncryptionHandle.test";
import { CryptoSecretKeyHandleTest } from "./crypto-layer/encryption/CryptoSecretKeyHandle.test";

export const TEST_PROVIDER_IDENT: ProviderIdentifier = { providerName: "SoftwareProvider" };

// eslint-disable-next-line @typescript-eslint/no-floating-promises
(async function () {
    await Promise.all([
        initCryptoLayerProviders({
            factoryFunctions: { getAllProviders, createProvider, createProviderFromName, getProviderCapabilities },
            providersToBeInitialized: [
                [
                    TEST_PROVIDER_IDENT,
                    {
                        // eslint-disable-next-line @typescript-eslint/naming-convention
                        additional_config: [
                            // eslint-disable-next-line @typescript-eslint/naming-convention
                            { StorageConfigPass: "12345678" },
                            // eslint-disable-next-line @typescript-eslint/naming-convention
                            { FileStoreConfig: { db_dir: "./test_cal_db" } }
                        ]
                    }
                ]
            ]
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
