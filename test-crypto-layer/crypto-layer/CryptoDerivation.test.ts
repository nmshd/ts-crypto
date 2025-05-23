import {
    CoreBuffer,
    CryptoCipher,
    CryptoDerivationHandle,
    CryptoEncryptionHandle,
    CryptoLayerUtils
} from "@nmshd/crypto";
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

                const derivedKey = await CryptoDerivationHandle.deriveKeyFromBaseKeyHandle(keyHandle, 1234, "testTest");
                await assertSecretKeyHandleValid(derivedKey);

                const derivedKey2 = await CryptoDerivationHandle.deriveKeyFromBaseKeyHandle(
                    keyHandle,
                    1234,
                    "testTest"
                );
                await assertSecretKeyHandleValid(derivedKey2);

                await assertSecretKeyHandleEqual(derivedKey, derivedKey2);
                expect(derivedKey.spec).to.deep.eq({ ...keyHandle.spec, ephemeral: true });

                const payload = CoreBuffer.fromUtf8("Hello World!");

                const encryptedPayload = await CryptoEncryptionHandle.encrypt(payload, derivedKey);

                expect(encryptedPayload).to.exist;
                expect(encryptedPayload).to.be.instanceOf(CryptoCipher);
                expect(encryptedPayload.algorithm).to.be.equal(
                    CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(derivedKey.spec.cipher)
                );
                expect(encryptedPayload.counter).to.not.exist;
                expect(encryptedPayload.nonce).to.exist;
                expect(encryptedPayload.nonce?.buffer.byteLength).to.be.greaterThanOrEqual(12);

                const decryptedPayload = await CryptoEncryptionHandle.decrypt(encryptedPayload, derivedKey2);

                expect(decryptedPayload).to.deep.equal(payload);
            });
        });
    }
}
