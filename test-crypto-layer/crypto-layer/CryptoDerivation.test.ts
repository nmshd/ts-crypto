import {
    CoreBuffer,
    CryptoDerivationAlgorithm,
    CryptoDerivationHandle,
    CryptoEncryptionHandle,
    DeviceBoundDerivedKeyHandle,
    PortableDerivedKeyHandle
} from "@nmshd/crypto";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../index";
import { parameterizedKeySpec } from "./CryptoLayerTestUtil";
import { assertSecretKeyHandleEqual, assertSecretKeyHandleValid } from "./KeyValidation";

export class CryptoDerivationHandleTest {
    public static run(): void {
        describe("CryptoDerivationHandle", function () {
            parameterizedKeySpec("should derive from device bound key handle", async function (crypto, hash) {
                const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                    TEST_PROVIDER_IDENT,
                    crypto,
                    hash
                );

                const derivedKey = await CryptoDerivationHandle.deriveDeviceBoundKeyHandle(keyHandle, 1234, "testTest");
                await assertSecretKeyHandleValid(derivedKey);
                expect(derivedKey).instanceOf(DeviceBoundDerivedKeyHandle);

                const derivedKey2 = await CryptoDerivationHandle.deriveDeviceBoundKeyHandle(
                    keyHandle,
                    1234,
                    "testTest"
                );
                await assertSecretKeyHandleValid(derivedKey2);
                expect(derivedKey2).instanceOf(DeviceBoundDerivedKeyHandle);

                await assertSecretKeyHandleEqual(derivedKey, derivedKey2);
            });

            parameterizedKeySpec("should derive from portable key handle", async function (crypto, hash) {
                const keyHandle = await CryptoEncryptionHandle.generatePortableKeyHandle(
                    TEST_PROVIDER_IDENT,
                    crypto,
                    hash
                );

                const derivedKey = await CryptoDerivationHandle.derivePortableKeyHandle(keyHandle, 1234, "testTest");
                await assertSecretKeyHandleValid(derivedKey);
                expect(derivedKey).instanceOf(PortableDerivedKeyHandle);

                const derivedKey2 = await CryptoDerivationHandle.derivePortableKeyHandle(keyHandle, 1234, "testTest");
                await assertSecretKeyHandleValid(derivedKey2);
                expect(derivedKey2).instanceOf(PortableDerivedKeyHandle);

                await assertSecretKeyHandleEqual(derivedKey, derivedKey2);
            });

            parameterizedKeySpec("should derive device bound key handle from password", async function (crypto, hash) {
                const keyHandle = await CryptoDerivationHandle.deriveDeviceBoundKeyHandleFromPassword({
                    providerIdent: TEST_PROVIDER_IDENT,
                    password: CoreBuffer.fromUtf8("password1234"),
                    salt: CoreBuffer.fromUtf8("1234"),
                    resultingKeyEncryptionAlgorithm: crypto,
                    resultingKeyHashAlgorithm: hash,
                    derivationAlgorithm: CryptoDerivationAlgorithm.ARGON2ID,
                    derivationIterations: 1,
                    derivationMemoryLimit: 1024,
                    derivationParallelism: 1
                });

                await assertSecretKeyHandleValid(keyHandle);
            });

            parameterizedKeySpec("should derive portable key handle from password", async function (crypto, hash) {
                const keyHandle = await CryptoDerivationHandle.derivePortableKeyHandleFromPassword({
                    providerIdent: TEST_PROVIDER_IDENT,
                    password: CoreBuffer.fromUtf8("password1234"),
                    salt: CoreBuffer.fromUtf8("1234"),
                    resultingKeyEncryptionAlgorithm: crypto,
                    resultingKeyHashAlgorithm: hash,
                    derivationAlgorithm: CryptoDerivationAlgorithm.ARGON2ID,
                    derivationIterations: 1,
                    derivationMemoryLimit: 1024,
                    derivationParallelism: 1
                });

                await assertSecretKeyHandleValid(keyHandle);
            });
        });
    }
}
