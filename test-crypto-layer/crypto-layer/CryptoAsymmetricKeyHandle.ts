import { assertKeyPairHandle, assertProvider } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";

import { CryptoAsymmetricKeyHandle } from "src/crypto-layer";

export function assertCryptoAsymmetricKeyHandle<T extends CryptoAsymmetricKeyHandle>(value: T) {
    expect(value).to.exist;
    expect(value.id).to.exist.and.to.be.a("string");
    expect(value.keyPairHandle).to.exist;
    expect(value.provider).to.exist;
    expect(value.providerName).to.exist.and.to.be.a("string");

    assertKeyPairHandle(value.keyPairHandle);
    assertProvider(value.provider);
}
