import { Serializable } from "@js-soft/ts-serval";
import { expect } from "chai";

export class CryptoReflectionTest {
    public static classNames: string[] = [
        "CoreBuffer@1",
        "CryptoCipher@1",
        "CryptoSecretKey@1",
        "CryptoExchangeKeypair@1",
        "CryptoExchangePrivateKey@1",
        "CryptoExchangePublicKey@1",
        "CryptoExchangeSecrets@1",
        "CryptoRelationshipPublicRequest@1",
        "CryptoRelationshipPublicResponse@1",
        "CryptoRelationshipRequestSecrets@1",
        "CryptoRelationshipSecrets@1",
        "CryptoSignatureKeypair@1",
        "CryptoSignaturePrivateKey@1",
        "CryptoSignaturePublicKey@1",
        "CryptoSignature@1",
        "CryptoPrivateStateReceive@1",
        "CryptoPrivateStateTransmit@1",
        "CryptoPublicState@1"
    ];
    public static run(): void {
        describe("CryptoReflection", function () {
            it("should register all required reflection classes", function () {
                const reflectionKeys = Reflect.getMetadataKeys(Serializable, "types");
                for (const className of CryptoReflectionTest.classNames) {
                    expect(reflectionKeys.includes(className)).equals(
                        true,
                        `Required class ${className} is not registered within Serializable reflection classes.`
                    );
                }
            });
        });
    }
}
