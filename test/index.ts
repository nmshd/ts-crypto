import { initCryptoLayerProviders, SodiumWrapper } from "@nmshd/crypto";
import {
    createProvider,
    createProviderFromName,
    getAllProviders,
    getProviderCapabilities
} from "@nmshd/rs-crypto-node";
import { BufferTest } from "./BufferTest.test";
import { CryptoLayerProviderTest } from "./crypto-layer/CryptoLayerProviderTest.test";
import { CryptoDerivationTest } from "./crypto/CryptoDerivationTest.test";
import { CryptoEncryptionTest } from "./crypto/CryptoEncryptionTest.test";
import { CryptoExchangeTest } from "./crypto/CryptoExchangeTest.test";
import { CryptoHashTest } from "./crypto/CryptoHashTest.test";
import { CryptoPasswordGeneratorTest } from "./crypto/CryptoPasswordGeneratorTest.test";
import { CryptoPrivateKeyTest } from "./crypto/CryptoPrivateKeyTest.test";
import { CryptoPublicKeyTest } from "./crypto/CryptoPublicKeyTest.test";
import { CryptoRandomTest } from "./crypto/CryptoRandomTest.test";
import { CryptoReflectionTest } from "./crypto/CryptoReflectionTest.test";
import { CryptoRelationshipTest } from "./crypto/CryptoRelationshipTest.test";
import { CryptoSecretKeyTest } from "./crypto/CryptoSecretKeyTest.test";
import { CryptoSignatureTest } from "./crypto/CryptoSignature.test";
import { CryptoStateTest } from "./crypto/CryptoStateTest.test";
import { SodiumWrapperTest } from "./crypto/SodiumWrapperTest.test";

SodiumWrapper.ready()
    .then(() => {
        SodiumWrapperTest.run();
        CryptoDerivationTest.run();
        CryptoReflectionTest.run();
        CryptoRelationshipTest.run();
        CryptoEncryptionTest.run();
        CryptoHashTest.run();
        CryptoExchangeTest.run();
        CryptoPrivateKeyTest.run();
        CryptoPublicKeyTest.run();
        CryptoRandomTest.run();
        CryptoPasswordGeneratorTest.run();
        CryptoSecretKeyTest.run();
        CryptoSignatureTest.run();
        CryptoStateTest.run();
        BufferTest.run();
    })
    .catch((e) => console.log(e));

initCryptoLayerProviders({
    factoryFunctions: { getAllProviders, createProvider, createProviderFromName, getProviderCapabilities },
    // eslint-disable-next-line @typescript-eslint/naming-convention
    keyMetadataStoreConfig: { FileStoreConfig: { db_dir: "./test_cal_db" } },
    // eslint-disable-next-line @typescript-eslint/naming-convention
    keyMetadataStoreAuth: { StorageConfigPass: "12345678" },
    providersToBeInitialized: [{ providerName: "SoftwareProvider" }]
})
    .then(() => {
        CryptoLayerProviderTest.run();
    })
    .catch((e) => console.log(e));
