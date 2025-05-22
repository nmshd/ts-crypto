/* eslint-disable @typescript-eslint/naming-convention */
import { CryptoEncryptionHandle, CryptoSecretKeyHandle } from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { TEST_PROVIDER_IDENT } from "test-crypto-layer";
import { testSerializeDeserializeOfBase64AndJson } from "../CommonSerialize";
import { assertSecretKeyHandleEqual, assertSecretKeyHandleValid } from "../KeyValidation";

export class CryptoSecretKeyHandleTest {
    public static run(): void {
        describe("CryptoSecretKeyHandle", function () {
            const spec: KeySpec = {
                cipher: "XChaCha20Poly1305",
                signing_hash: "Sha2_256",
                ephemeral: false
            };

            testSerializeDeserializeOfBase64AndJson(
                "CryptoSecretKeyHandle",
                async () => {
                    return await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);
                },
                CryptoSecretKeyHandle,
                assertSecretKeyHandleValid,
                assertSecretKeyHandleEqual
            );
        });
    }
}
