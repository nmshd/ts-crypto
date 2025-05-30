import { CryptoDerivationHandle, CryptoEncryptionHandle } from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { TEST_PROVIDER_IDENT } from "../index";
import { parameterizedKeySpec } from "./CryptoLayerTestUtil";
import { assertSecretKeyHandleEqual, assertSecretKeyHandleValid } from "./KeyValidation";

export class CryptoDerivationHandleTest {
    public static run(): void {
        describe("CryptoDerivationHandle", function () {
            parameterizedKeySpec(
                "generateDeviceBoundKeyHandle",
                async function (spec: KeySpec) {
                    const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                        TEST_PROVIDER_IDENT,
                        spec
                    );

                    const derivedKey = await CryptoDerivationHandle.deriveDeviceBoundKeyHandle(
                        keyHandle,
                        1234,
                        "testTest"
                    );
                    await assertSecretKeyHandleValid(derivedKey);

                    const derivedKey2 = await CryptoDerivationHandle.deriveDeviceBoundKeyHandle(
                        keyHandle,
                        1234,
                        "testTest"
                    );
                    await assertSecretKeyHandleValid(derivedKey2);

                    await assertSecretKeyHandleEqual(derivedKey, derivedKey2);
                },
                {
                    ephemeral: [false],
                    nonExportable: [true]
                }
            );

            parameterizedKeySpec(
                "generatePortableKeyHandle",
                async function (spec: KeySpec) {
                    const keyHandle = await CryptoEncryptionHandle.generatePortableKeyHandle(TEST_PROVIDER_IDENT, spec);

                    const derivedKey = await CryptoDerivationHandle.deriveDeviceBoundKeyHandle(
                        keyHandle,
                        1234,
                        "testTest"
                    );
                    await assertSecretKeyHandleValid(derivedKey);

                    const derivedKey2 = await CryptoDerivationHandle.deriveDeviceBoundKeyHandle(
                        keyHandle,
                        1234,
                        "testTest"
                    );
                    await assertSecretKeyHandleValid(derivedKey2);

                    await assertSecretKeyHandleEqual(derivedKey, derivedKey2);
                },
                {
                    ephemeral: [false],
                    nonExportable: [false]
                }
            );
        });
    }
}
