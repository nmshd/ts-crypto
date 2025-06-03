import { getProvider } from "@nmshd/crypto";
import { assertProvider } from "@nmshd/rs-crypto-types/checks";
import { expect } from "chai";
import { TEST_PROVIDER_IDENT } from "../index";

export class CryptoLayerProviderTest {
    public static run(): void {
        describe("CryptoLayerProvider", function () {
            it("getProvider() should return a valid provider", async function () {
                const provider = getProvider(TEST_PROVIDER_IDENT);
                expect(provider).to.exist;
                assertProvider(provider);
                if ("providerName" in TEST_PROVIDER_IDENT) {
                    expect(await provider.providerName()).to.equal(TEST_PROVIDER_IDENT.providerName);
                } else if ("securityLevel" in TEST_PROVIDER_IDENT) {
                    const capabilities = await provider.getCapabilities();
                    expect(capabilities?.min_security_level).to.eq(TEST_PROVIDER_IDENT.securityLevel);
                }
            });
        });
    }
}
