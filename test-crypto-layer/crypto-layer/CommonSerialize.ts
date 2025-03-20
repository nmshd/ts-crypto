import { expect } from "chai";
import { CryptoAsymmetricKeyHandle } from "src/crypto-layer";
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
async function CommonSerializeTest<T>(
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

export async function TestSerializeDeserializeOfBase64AndJson<T extends ToBase64<T> & ToJson<T>>(
    name: string,
    create: () => Promise<T>,
    constructor: { new (): T } & FromBase64<T> & FromJson<T>,
    validator: (value: T) => Promise<void>,
    beforeAfterValidator: (beforeSerialization: T, afterSerialization: T) => Promise<void>
) {
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

    CommonSerializeTest(name, create, serializers, validator, beforeAfterValidator);
}

/**
 * Tests AsymmetricKeyPairHandle for validity and executes the id function.
 */
export async function assertCryptoAsymmetricKeyHandleWithUse<T extends CryptoAsymmetricKeyHandle>(handle: T) {
    assertCryptoAsymmetricKeyHandle(handle);
    expect(await handle.keyPairHandle.id()).to.exist.and.to.be.a("string").and.to.be.not.empty;
    expect(await handle.keyPairHandle.spec()).to.deep.equal(handle.spec);
}

export async function assertBeforeAfterAsymmetricKeyHandle<T extends CryptoAsymmetricKeyHandle>(before: T, after: T) {
    expect(before.spec).to.deep.equal(after.spec);
}

/**
 * Tests CryptoAsymmetricKeyHandle for serialization and deserialization.
 */
export async function TestSerializeDeserializeOfAsymmetricKeyPairHandle<
    T extends CryptoAsymmetricKeyHandle & ToBase64<T> & ToJson<T>
>(name: string, create: () => Promise<T>, constructor: { new (): T } & FromBase64<T> & FromJson<T>) {
    const validator = async (handle: T) => {
        await assertCryptoAsymmetricKeyHandleWithUse(handle);
    };

    TestSerializeDeserializeOfBase64AndJson(name, create, constructor, validator, assertBeforeAfterAsymmetricKeyHandle);
}

/**
 * Tests KeyPairHandle holding CryptoAsymmetricKeyHandle for serialization and deserialization.
 */
export async function TestSerializeDeserializeOfCryptoKeyPairHandle<
    I extends CryptoAsymmetricKeyHandle & ToBase64<I> & ToJson<I>,
    T extends { publicKey: I; privateKey: I } & ToBase64<T> & ToJson<T>
>(name: string, create: () => Promise<T>, constructor: { new (): T } & FromBase64<T> & FromJson<T>) {
    const validator = async (handle: T) => {
        await assertCryptoAsymmetricKeyHandleWithUse(handle.privateKey);
        await assertCryptoAsymmetricKeyHandleWithUse(handle.publicKey);
    };

    const beforeAfterValidator = async (before: T, after: T) => {
        await assertBeforeAfterAsymmetricKeyHandle(before.privateKey, after.privateKey);
        await assertBeforeAfterAsymmetricKeyHandle(before.publicKey, after.privateKey);
    };

    TestSerializeDeserializeOfBase64AndJson(name, create, constructor, validator, beforeAfterValidator);
}
