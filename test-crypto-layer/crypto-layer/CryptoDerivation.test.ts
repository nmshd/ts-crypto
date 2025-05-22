import { CoreBuffer, CryptoDerivationHandle, CryptoEncryptionHandle } from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../index";
import { parameterizedKeySpec } from "./CryptoLayerTestUtil";
import { assertSecretKeyHandleEqual, assertSecretKeyHandleValid } from "./KeyValidation";

export class CryptoDerivationHandleTest {
    public static run(): void {
        describe("CryptoDerivationHandle", function () {
            parameterizedKeySpec("deriveKeyHandleFromBase", async function (spec: KeySpec) {
                const keyHandle = await CryptoEncryptionHandle.generateKey(TEST_PROVIDER_IDENT, spec);

                const derivedKey = await CryptoDerivationHandle.deriveKeyHandleFromBase(keyHandle, 1234, "testTest");
                await assertSecretKeyHandleValid(derivedKey);

                const derivedKey2 = await CryptoDerivationHandle.deriveKeyHandleFromBase(keyHandle, 1234, "testTest");
                await assertSecretKeyHandleValid(derivedKey2);

                await assertSecretKeyHandleEqual(derivedKey, derivedKey2);
                expect(derivedKey.spec).to.deep.eq({ ...keyHandle.spec, ephemeral: true });

                const encoder = new TextEncoder();
                const payload = new CoreBuffer(encoder.encode("Hello World!"));

                const encryptedPayload = await CryptoEncryptionHandle.encrypt(payload, derivedKey);

                const decryptedPayload = await CryptoEncryptionHandle.decrypt(encryptedPayload, derivedKey2);

                expect(decryptedPayload).to.deep.equal(payload);
            });
        });
    }
}
