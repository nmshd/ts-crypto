import { SodiumWrapper } from "@nmshd/crypto";
import { expect } from "chai";

export class SodiumWrapperTest {
    public static run(): void {
        describe("SodiumWrapper", function () {
            it("should load libsodium", async function () {
                const s: any = await SodiumWrapper.ready();
                if (typeof window !== "undefined") {
                    (window as any).sodium = s;
                }
                expect(s).to.exist;
            });
        });
    }
}
