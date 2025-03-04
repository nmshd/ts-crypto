import { CryptoSignatures } from "@nmshd/crypto";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { CryptoSignatureKeypairHandle } from "src/crypto-layer/signature/CryptoSignatureKeypair";
import { CryptoSignaturePrivateKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePrivateKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import { parameterizedKeyPairSpec } from "./CryptoLayerTestUtil";

export async function expectCryptoSignatureKeypairHandle(
    cryptoKeyPairHandle: CryptoSignatureKeypairHandle,
    expectedProvider: string,
    spec: KeyPairSpec
): Promise<void> {
    expect(cryptoKeyPairHandle).to.be.instanceOf(CryptoSignatureKeypairHandle);
    expect(cryptoKeyPairHandle.privateKey).to.be.instanceOf(CryptoSignaturePrivateKeyHandle);
    expect(cryptoKeyPairHandle.publicKey).to.be.instanceOf(CryptoSignaturePublicKeyHandle);
    expect(cryptoKeyPairHandle.privateKey.keyPairHandle).to.be.ok.and.deep.equal(
        cryptoKeyPairHandle.publicKey.keyPairHandle
    );
    expect(cryptoKeyPairHandle.privateKey.id)
        .to.be.a("string")
        .and.to.equal(await cryptoKeyPairHandle.privateKey.keyPairHandle.id());
    expect(cryptoKeyPairHandle.publicKey.id)
        .to.be.a("string")
        .and.to.equal(await cryptoKeyPairHandle.publicKey.keyPairHandle.id())
        .and.to.be.string(cryptoKeyPairHandle.privateKey.id);

    expect(cryptoKeyPairHandle.privateKey.provider).to.be.ok.and.deep.equal(cryptoKeyPairHandle.publicKey.provider);
    expect(cryptoKeyPairHandle.privateKey.providerName)
        .to.be.a("string")
        .and.to.be.string(cryptoKeyPairHandle.publicKey.providerName)
        .and.to.be.string(expectedProvider);
    expect(await cryptoKeyPairHandle.privateKey.keyPairHandle.spec()).to.deep.equal(spec);
    expect(await cryptoKeyPairHandle.publicKey.keyPairHandle.spec()).to.deep.equal(spec);
}

export class CryptoSignatureKeypairHandleTest {
    public static run(): void {
        describe("CryptoSignatureKeypairHandle", function () {
            describe("generateKeyPairHandle() SoftwareProvider", function () {
                parameterizedKeyPairSpec("generateKeyPairHandle()", async function (spec: KeyPairSpec) {
                    const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(
                        { providerName: "SoftwareProvider" },
                        spec
                    );
                    await expectCryptoSignatureKeypairHandle(cryptoKeyPairHandle, "SoftwareProvider", spec);
                });
            });
        });
    }
}
