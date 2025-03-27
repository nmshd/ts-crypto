import { CryptoAsymmetricKeyHandle } from "@nmshd/crypto";
import { assertKeyPairHandle, assertProvider } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";

/**
 * Tests AsymmetricKeyPairHandle for validity and executes the id function.
 */
export async function assertAsymmetricKeyHandleValid<T extends CryptoAsymmetricKeyHandle>(handle: T) {
    expect(handle).to.exist;
    expect(handle.id).to.exist.and.to.be.a("string");
    expect(handle.keyPairHandle).to.exist;
    expect(handle.provider).to.exist;
    expect(handle.providerName).to.exist.and.to.be.a("string");

    assertKeyPairHandle(handle.keyPairHandle);
    assertProvider(handle.provider);

    expect(await handle.keyPairHandle.id()).to.exist.and.to.be.a("string").and.to.be.not.empty;
    expect(await handle.keyPairHandle.spec()).to.exist.and.to.deep.equal(handle.spec);
}

/**
 * Test that the content of two AsymmetricKeys match.
 */
export async function assertAsymmetricKeyHandleEqual<T extends CryptoAsymmetricKeyHandle>(before: T, after: T) {
    expect(before.spec).to.deep.equal(after.spec);
    expect(await before.keyPairHandle.getPublicKey()).to.exist.and.to.deep.equal(
        await after.keyPairHandle.getPublicKey()
    );
    if (before.spec.non_exportable || after.spec.non_exportable) return;
    expect(await before.keyPairHandle.extractKey()).to.exist.and.to.deep.equal(await after.keyPairHandle.extractKey());
}

type CryptoKeyPairHandle<I extends CryptoAsymmetricKeyHandle> = {
    publicKey: I;
    privateKey: I;
};

export async function assertCryptoKeyPairHandleValid<T extends CryptoAsymmetricKeyHandle>(
    value: CryptoKeyPairHandle<T>
) {
    await assertAsymmetricKeyHandleValid(value.privateKey);
    await assertAsymmetricKeyHandleValid(value.publicKey);
}

export async function assertCryptoKeyPairHandleEqual<T extends CryptoAsymmetricKeyHandle>(
    before: CryptoKeyPairHandle<T>,
    after: CryptoKeyPairHandle<T>
) {
    await assertAsymmetricKeyHandleEqual(before.privateKey, after.privateKey);
    await assertAsymmetricKeyHandleEqual(before.publicKey, after.privateKey);
}
