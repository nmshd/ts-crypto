import { Serializable } from "@js-soft/ts-serval";
import { expect } from "chai";

export class CryptoReflectionTest {
    public static classNames: string[] = [
        "CryptoCipher",
        "CryptoSecretKey",
        "CryptoExchangeKeypair",
        "CryptoExchangePrivateKey",
        "CryptoExchangePublicKey",
        "CryptoExchangeSecrets",
        "CryptoRelationshipPublicRequest",
        "CryptoRelationshipPublicResponse",
        "CryptoRelationshipRequestSecrets",
        "CryptoRelationshipSecrets",
        "CryptoSignatureKeypair",
        "CryptoSignaturePrivateKey",
        "CryptoSignaturePublicKey",
        "CryptoSignature",
        "CryptoPrivateStateReceive",
        "CryptoPrivateStateTransmit",
        "CryptoPublicState",
        "CoreBuffer",
        "CryptoSerializableAsync"
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
