import {
    BaseKeyHandle,
    CoreBuffer,
    CryptoCipher,
    CryptoEncryptionHandle,
    CryptoLayerUtils,
    DeviceBoundDerivedKeyHandle,
    DeviceBoundKeyHandle,
    PortableDerivedKeyHandle,
    PortableKeyHandle
} from "@nmshd/crypto";
import { assertKeyHandle, assertKeySpec, assertProvider } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";

/**
 * Tests SecretKeyHandle for validity and executes the id function.
 */
export async function assertSecretKeyHandleValid<T extends BaseKeyHandle>(handle: T): Promise<void> {
    expect(handle).to.exist;
    expect(handle.id).to.exist.and.to.be.a("string");
    expect(handle.keyHandle).to.exist;
    expect(handle.provider).to.exist;
    expect(handle.spec).to.exist;
    expect(handle.providerName).to.exist.and.to.be.a("string");

    assertKeyHandle(handle.keyHandle);
    assertProvider(handle.provider);
    assertKeySpec(handle.spec);

    expect(await handle.keyHandle.id()).to.exist.and.to.be.a("string").and.to.be.not.empty;
    expect(await handle.keyHandle.spec()).to.exist.and.to.deep.equal(handle.spec);

    if (handle instanceof DeviceBoundKeyHandle) {
        expect(handle.spec.ephemeral).to.be.false;
        expect(handle.spec.non_exportable).to.be.true;
    } else if (handle instanceof DeviceBoundDerivedKeyHandle) {
        expect(handle.spec.ephemeral).to.be.true;
        expect(handle.spec.non_exportable).to.be.true;
    } else if (handle instanceof PortableKeyHandle) {
        expect(handle.spec.ephemeral).to.be.false;
        expect(handle.spec.non_exportable).to.be.false;
    } else if (handle instanceof PortableDerivedKeyHandle) {
        expect(handle.spec.ephemeral).to.be.true;
        expect(handle.spec.non_exportable).to.be.false;
    } else {
        throw new Error("Test: unknown key handle instance.");
    }
}

async function testDecryptEncryptIsIdentityFunction<T extends BaseKeyHandle>(before: T, after: T): Promise<void> {
    const payload = CoreBuffer.fromUtf8("Hello World!");

    const encryptedPayload = await CryptoEncryptionHandle.encrypt(payload, before);

    expect(encryptedPayload).to.exist;
    expect(encryptedPayload).to.be.instanceOf(CryptoCipher);
    expect(encryptedPayload.algorithm).to.be.equal(
        CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(before.spec.cipher)
    );
    expect(encryptedPayload.counter).to.not.exist;
    expect(encryptedPayload.nonce).to.exist;
    expect(encryptedPayload.nonce?.buffer.byteLength).to.be.greaterThanOrEqual(12);

    const decryptedPayload = await CryptoEncryptionHandle.decrypt(encryptedPayload, after);

    expect(decryptedPayload).to.deep.equal(payload);
}

/**
 * Test that the content of two SecretKeys match.
 */
export async function assertSecretKeyHandleEqual<T extends BaseKeyHandle>(before: T, after: T): Promise<void> {
    expect(before.spec).to.deep.equal(after.spec);
    if (
        (before instanceof PortableKeyHandle && after instanceof PortableKeyHandle) ||
        (before instanceof PortableDerivedKeyHandle && after instanceof PortableDerivedKeyHandle)
    ) {
        expect((await CryptoEncryptionHandle.extractRawKey(before)).buffer).to.deep.eq(
            (await CryptoEncryptionHandle.extractRawKey(after)).buffer
        );
    } else {
        await testDecryptEncryptIsIdentityFunction(before, after);
    }
}
