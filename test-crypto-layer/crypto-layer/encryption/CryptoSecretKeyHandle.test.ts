/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoEncryptionHandle, DeviceBoundKeyHandle, PortableKeyHandle } from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "test-crypto-layer";
import { testSerializeDeserializeOfBase64AndJson } from "../CommonSerialize";
import { parameterizedKeySpec } from "../CryptoLayerTestUtil";
import { assertSecretKeyHandleEqual, assertSecretKeyHandleValid } from "../KeyValidation";

export class CryptoSecretKeyHandleTest {
    public static run(): void {
        describe("PortableKeyHandle and DeviceBoundKeyHandle", function () {
            const portableSpec: KeySpec = {
                cipher: "XChaCha20Poly1305",
                signing_hash: "Sha2_256",
                ephemeral: false,
                non_exportable: false
            };

            testSerializeDeserializeOfBase64AndJson(
                "PortableKeyHandle",
                async () => {
                    return await CryptoEncryptionHandle.generatePortableKeyHandle(TEST_PROVIDER_IDENT, portableSpec);
                },
                PortableKeyHandle,
                assertSecretKeyHandleValid,
                assertSecretKeyHandleEqual
            );

            const deviceBoundSpec: KeySpec = {
                cipher: "XChaCha20Poly1305",
                signing_hash: "Sha2_256",
                ephemeral: false,
                non_exportable: true
            };

            testSerializeDeserializeOfBase64AndJson(
                "DeviceBoundKeyHandle",
                async () => {
                    return await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                        TEST_PROVIDER_IDENT,
                        deviceBoundSpec
                    );
                },
                DeviceBoundKeyHandle,
                assertSecretKeyHandleValid,
                assertSecretKeyHandleEqual
            );

            parameterizedKeySpec(
                "from IBaseKeyHandle should load a device bound key handle",
                async function (spec: KeySpec) {
                    const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                        TEST_PROVIDER_IDENT,
                        spec
                    );
                    await assertSecretKeyHandleValid(keyHandle);

                    const loadedKeyHandle = await DeviceBoundKeyHandle.from({
                        id: keyHandle.id,
                        spec: keyHandle.spec,
                        providerName: keyHandle.providerName
                    });

                    expect(loadedKeyHandle).instanceOf(DeviceBoundKeyHandle);

                    await Promise.all([
                        assertSecretKeyHandleValid(loadedKeyHandle),
                        assertSecretKeyHandleEqual(keyHandle, loadedKeyHandle)
                    ]);
                },
                {
                    ephemeral: [false],
                    nonExportable: [true]
                }
            );

            parameterizedKeySpec(
                "from DeviceBoundKeyHandle should load a device bound key handle",
                async function (spec: KeySpec) {
                    const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                        TEST_PROVIDER_IDENT,
                        spec
                    );
                    await assertSecretKeyHandleValid(keyHandle);

                    const loadedKeyHandle = await DeviceBoundKeyHandle.from(keyHandle);

                    expect(loadedKeyHandle).instanceOf(DeviceBoundKeyHandle);

                    await Promise.all([
                        assertSecretKeyHandleValid(loadedKeyHandle),
                        assertSecretKeyHandleEqual(keyHandle, loadedKeyHandle)
                    ]);
                },
                {
                    ephemeral: [false],
                    nonExportable: [true]
                }
            );
        });
    }
}
