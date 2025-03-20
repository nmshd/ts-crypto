import { expect } from "chai";
import { CryptoAsymmetricKeyHandle, CryptoSecretKeyHandle } from "src/crypto-layer";
import { assertCryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle";

type SerializePair<ClassToTest, IntermediaryFormat> = [
    (value: ClassToTest) => IntermediaryFormat,
    (value: IntermediaryFormat) => Promise<ClassToTest>
];

type SerializerVec<T> = [SerializePair<T, string> | SerializePair<T, Object>, string][];

/**
 * Generates tests for common serialize and deserialize functions.
 *
 * @param constructor Constructor of the class. Used for executing static methods.
 * @param create A function that returns the class that is to be tested.
 * @param serializers Functions that are to be tested.
 * @param validator A function that validates that the class is correct. Uses expect from chai and type guards, which throw.
 * @param beforeAfterValidator A function that validates that the deserialized result has expected values compared to the original (like `spec()`).
 */
async function CommonSerializeTest<T extends CryptoAsymmetricKeyHandle | CryptoSecretKeyHandle>(
    name: string,
    create: () => Promise<T>,
    serializers: SerializerVec<T>,
    validator: (value: T) => Promise<void>,
    beforeAfterValidator: (beforeSerialization: T, afterSerialization: T) => Promise<void>
) {
    describe(`Serialize Deserialize Tests - ${name}`, () => {
        for (const [[serialize, deserialize], serializeTestName] of serializers) {
            it(serializeTestName, async () => {
                const handle = await create();
                validator(handle);

                const serialized = serialize(handle);
                const deserialized = (await (deserialize as any)(serialized)) as T;
                validator(deserialized);
                beforeAfterValidator(handle, deserialized);
            });
        }
    });
}

type ToBase64<T> = {
    toBase64(this: T, verbose?: boolean): string;
};

type FromBase64<T> = {
    fromBase64: (value: string) => Promise<T>;
};

type ToJson<T> = {
    toJSON(verbose?: boolean): Object;
};

type FromJson<T> = {
    fromJSON(value: Object): Promise<T>;
};

export async function TestSerializeDeserializeOfAsymmetricKeyPairHandle<
    T extends CryptoAsymmetricKeyHandle & ToBase64<T> & ToJson<T>
>(name: string, create: () => Promise<T>, constructor: { new (): T } & FromBase64<T> & FromJson<T>) {
    const objectForStaticCalls = await create();

    const toAndFromBase64: SerializePair<T, string> = [
        (handle: T) => handle.toBase64(),
        async (serialized: string) => await constructor.fromBase64(serialized)
    ];
    const toAndFromJson: SerializePair<T, Object> = [
        (handle: T) => handle.toJSON(),
        async (serialized: Object) => await constructor.fromJSON(serialized)
    ];
    const serializers: SerializerVec<T> = [
        [toAndFromJson, "toJSON() and fromJSON()"],
        [toAndFromBase64, "toBase64() and fromBase64()"]
    ];

    const validator = async (handle: T) => {
        assertCryptoAsymmetricKeyHandle(handle);
        expect(await handle.keyPairHandle.id()).to.exist.and.to.be.a("string").and.to.be.not.empty;
        expect(await handle.keyPairHandle.spec()).to.deep.equal(handle.spec);
    };

    const beforeAfterValidator = async (before: T, after: T) => {
        expect(before.spec).to.deep.equal(after.spec);
    };

    CommonSerializeTest(name, create, serializers, validator, beforeAfterValidator);
}
