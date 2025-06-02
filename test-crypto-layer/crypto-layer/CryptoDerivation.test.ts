import {
    CoreBuffer,
    CryptoDerivationAlgorithm,
    CryptoDerivationHandle,
    CryptoEncryptionAlgorithm,
    CryptoEncryptionHandle,
    CryptoHashAlgorithm,
    DeviceBoundDerivedKeyHandle,
    PortableDerivedKeyHandle
} from "@nmshd/crypto";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../index";
import { expectThrows, parameterizedKeySpec } from "./CryptoLayerTestUtil";
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

            parameterizedKeySpec(
                "should derive device bound key handle from password and equal prior derivation",
                async function (crypto, hash) {
                    const derivationConfig = {
                        providerIdent: TEST_PROVIDER_IDENT,
                        password: CoreBuffer.fromUtf8("password1234"),
                        salt: CoreBuffer.fromUtf8("12345678"),
                        resultingKeyEncryptionAlgorithm: crypto,
                        resultingKeyHashAlgorithm: hash,
                        derivationAlgorithm: CryptoDerivationAlgorithm.ARGON2ID,
                        derivationIterations: 1,
                        derivationMemoryLimit: 1024,
                        derivationParallelism: 1
                    };

                    const keyHandle =
                        await CryptoDerivationHandle.deriveDeviceBoundKeyHandleFromPassword(derivationConfig);
                    await assertSecretKeyHandleValid(keyHandle);

                    const keyHandle2 =
                        await CryptoDerivationHandle.deriveDeviceBoundKeyHandleFromPassword(derivationConfig);
                    await assertSecretKeyHandleValid(keyHandle2);

                    await assertSecretKeyHandleEqual(keyHandle, keyHandle2);
                }
            );

            parameterizedKeySpec(
                "should derive portable key handle from password and equal prior derivation",
                async function (crypto, hash) {
                    const derivationConfig = {
                        providerIdent: TEST_PROVIDER_IDENT,
                        password: CoreBuffer.fromUtf8("password1234"),
                        salt: CoreBuffer.fromUtf8("12345678"),
                        resultingKeyEncryptionAlgorithm: crypto,
                        resultingKeyHashAlgorithm: hash,
                        derivationAlgorithm: CryptoDerivationAlgorithm.ARGON2ID,
                        derivationIterations: 1,
                        derivationMemoryLimit: 1024,
                        derivationParallelism: 1
                    };

                    const keyHandle =
                        await CryptoDerivationHandle.derivePortableKeyHandleFromPassword(derivationConfig);
                    await assertSecretKeyHandleValid(keyHandle);

                    const keyHandle2 =
                        await CryptoDerivationHandle.derivePortableKeyHandleFromPassword(derivationConfig);
                    await assertSecretKeyHandleValid(keyHandle2);

                    await assertSecretKeyHandleEqual(keyHandle, keyHandle2);
                }
            );

            it("should fail derivation with bad salt", async function () {
                const derivationConfig = {
                    providerIdent: TEST_PROVIDER_IDENT,
                    password: CoreBuffer.fromUtf8("password1234"),
                    salt: CoreBuffer.fromUtf8("12345"),
                    resultingKeyEncryptionAlgorithm: CryptoEncryptionAlgorithm.AES256_GCM,
                    resultingKeyHashAlgorithm: CryptoHashAlgorithm.SHA256,
                    derivationAlgorithm: CryptoDerivationAlgorithm.ARGON2ID,
                    derivationIterations: 1,
                    derivationMemoryLimit: 1024,
                    derivationParallelism: 1
                };

                await expectThrows(
                    CryptoDerivationHandle.derivePortableKeyHandleFromPassword(derivationConfig),
                    /Buffer within property salt has a minimum of 8 bytes/
                );
            });
        });
    }
}
