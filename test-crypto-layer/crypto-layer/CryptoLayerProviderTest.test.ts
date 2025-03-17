import { getProviderOrThrow } from "@nmshd/crypto";
import { expect } from "chai";

export class CryptoLayerProviderTest {
    public static run(): void {
        describe("CryptoLayerProvider", function () {
            it("getProvider() should return a valid provider", async function () {
                const provider = getProviderOrThrow({ providerName: "SoftwareProvider" });
                expect(provider).to.exist;
                expect(provider.createKey).to.exist.that.is.a("function");
                expect(provider.loadKey).to.exist.that.is.a("function");
                expect(provider.importKey).to.exist.that.is.a("function");
                expect(provider.createKeyPair).to.exist.that.is.a("function");
                expect(provider.loadKeyPair).to.exist.that.is.a("function");
                expect(provider.importKeyPair).to.exist.that.is.a("function");
                expect(provider.importPublicKey).to.exist.that.is.a("function");
                expect(provider.getCapabilities).to.exist.that.is.a("function");
                expect(provider.providerName).to.exist.that.is.a("function");
                expect(provider.startEphemeralDhExchange).to.exist.that.is.a("function");
                expect(await provider.providerName()).to.equal("SoftwareProvider");
            });
        });
    }
}
