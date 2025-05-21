import { CryptoSecretKeyHandle } from "@nmshd/crypto";
import { assertKeyHandle, assertProvider } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";

/**
 * Tests SecretKeyHandle for validity and executes the id function.
 */
export async function assertSecretKeyHandleValid<T extends CryptoSecretKeyHandle>(handle: T) {
    expect(handle).to.exist;
    expect(handle.id).to.exist.and.to.be.a("string");
    expect(handle.keyHandle).to.exist;
    expect(handle.provider).to.exist;
    expect(handle.providerName).to.exist.and.to.be.a("string");

    assertKeyHandle(handle.keyHandle);
    assertProvider(handle.provider);

    expect(await handle.keyHandle.id()).to.exist.and.to.be.a("string").and.to.be.not.empty;
    expect(await handle.keyHandle.spec()).to.exist.and.to.deep.equal(handle.spec);
}

/**
 * Test that the content of two SecretKeys match.
 */
export async function assertSecretKeyHandleEqual<T extends CryptoSecretKeyHandle>(before: T, after: T) {
    expect(before.spec).to.deep.equal(after.spec);
    expect(await before.keyHandle.extractKey()).to.deep.eq(await after.keyHandle.extractKey());
}
