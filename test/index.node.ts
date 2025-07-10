import { CryptoLayerProviderIdentifier, initializeNewProviders, SodiumWrapper } from "@nmshd/crypto";
import {
    createProvider,
    createProviderFromName,
    getAllProviders,
    getProviderCapabilities
} from "@nmshd/rs-crypto-node";
import { BufferTest } from "./BufferTest.test";
import { CryptoDerivationHandleTest } from "./cal/CryptoDerivation.test";
import { CryptoLayerConfigTest } from "./cal/CryptoLayerConfig.test";
import { CryptoEncryptionHandleTest } from "./cal/encryption/CryptoEncryptionHandle.test";
import { CryptoSecretKeyHandleTest } from "./cal/encryption/CryptoSecretKeyHandle.test";
import { CryptoLayerProviderInitializedTest } from "./cal/provider/CryptoLayerProviderInitializedTest.test";
import { CryptoLayerProvidersTest } from "./cal/provider/CryptoLayerProviders.test";
import { CryptoSignaturesHandleTest } from "./cal/signature/CryptoSignaturesHandle.test";
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

export const TEST_PROVIDER_IDENT: CryptoLayerProviderIdentifier = { securityLevel: "Software" };

Promise.all([
    initializeNewProviders(
        // eslint-disable-next-line @typescript-eslint/naming-convention
        { FileStoreConfig: { db_dir: "./test_cal_db" } },
        { getAllProviders, createProvider, createProviderFromName, getProviderCapabilities }
    ),
    SodiumWrapper.ready()
])
    .then(function () {
        CryptoLayerProviderInitializedTest.run();

        // Encryption
        CryptoSecretKeyHandleTest.run();
        CryptoEncryptionHandleTest.run();

        // Derivation
        CryptoDerivationHandleTest.run();

        // Signature
        CryptoSignaturesHandleTest.run();

        // Config
        CryptoLayerConfigTest.run();

        // Test Provider initialization via Mocks.
        CryptoLayerProvidersTest.run();
        // CryptoLayerProvidersTest REPLACES ALL PROVIDERS WITH MOCKS!
    })
    .catch((e) => console.log(e));
