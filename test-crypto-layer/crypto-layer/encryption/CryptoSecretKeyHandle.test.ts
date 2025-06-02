import {
    CryptoEncryptionAlgorithm,
    CryptoEncryptionHandle,
    CryptoHashAlgorithm,
    DeviceBoundKeyHandle,
    PortableKeyHandle
} from "@nmshd/crypto";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "test-crypto-layer";
import { testSerializeDeserializeOfBase64AndJson } from "../CommonSerialize";
import { parameterizedKeySpec } from "../CryptoLayerTestUtil";
import { assertSecretKeyHandleEqual, assertSecretKeyHandleValid } from "../KeyValidation";

export class CryptoSecretKeyHandleTest {
    public static run(): void {
        describe("PortableKeyHandle and DeviceBoundKeyHandle", function () {
            testSerializeDeserializeOfBase64AndJson(
                "PortableKeyHandle",
                async () => {
                    return await CryptoEncryptionHandle.generatePortableKeyHandle(
                        TEST_PROVIDER_IDENT,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoHashAlgorithm.SHA256
                    );
                },
                PortableKeyHandle,
                assertSecretKeyHandleValid,
                assertSecretKeyHandleEqual
            );

            testSerializeDeserializeOfBase64AndJson(
                "DeviceBoundKeyHandle",
                async () => {
                    return await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                        TEST_PROVIDER_IDENT,
                        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
                        CryptoHashAlgorithm.SHA256
                    );
                },
                DeviceBoundKeyHandle,
                assertSecretKeyHandleValid,
                assertSecretKeyHandleEqual
            );

            parameterizedKeySpec(
                "from IBaseKeyHandle should load a device bound key handle",
                async function (crypto, hash) {
                    const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                        TEST_PROVIDER_IDENT,
                        crypto,
                        hash
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
                }
            );

            parameterizedKeySpec(
                "from DeviceBoundKeyHandle should load a device bound key handle",
                async function (crypto, hash) {
                    const keyHandle = await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
                        TEST_PROVIDER_IDENT,
                        crypto,
                        hash
                    );
                    await assertSecretKeyHandleValid(keyHandle);

                    const loadedKeyHandle = await DeviceBoundKeyHandle.from(keyHandle);

                    expect(loadedKeyHandle).instanceOf(DeviceBoundKeyHandle);

                    await Promise.all([
                        assertSecretKeyHandleValid(loadedKeyHandle),
                        assertSecretKeyHandleEqual(keyHandle, loadedKeyHandle)
                    ]);
                }
            );
        });
    }
}
