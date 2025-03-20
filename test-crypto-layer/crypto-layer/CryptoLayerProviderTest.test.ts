import { getProviderOrThrow } from "@nmshd/crypto";
import { assertProvider } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";

export class CryptoLayerProviderTest {
    public static run(): void {
        describe("CryptoLayerProvider", function () {
            it("getProvider() should return a valid provider", async function () {
                const provider = getProviderOrThrow({ providerName: "SoftwareProvider" });
                expect(provider).to.exist;
                assertProvider(provider);
                expect(await provider.providerName()).to.equal("SoftwareProvider");
            });
        });
    }
}
