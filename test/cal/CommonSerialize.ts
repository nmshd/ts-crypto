type SerializePair<ClassToTest, IntermediaryFormat> = [
    (value: ClassToTest) => IntermediaryFormat,
    (value: IntermediaryFormat) => Promise<ClassToTest>
];

type SerializerVec<T> = [SerializePair<T, string> | SerializePair<T, Object>, string][];

function commonSerializeTest<T>(
    name: string,
    create: () => Promise<T>,
    serializers: SerializerVec<T>,
    validator: (value: T) => Promise<void>,
    beforeAfterValidator: (beforeSerialization: T, afterSerialization: T) => Promise<void>
) {
    describe(`Serialize Deserialize Tests - ${name}`, function () {
        for (const [[serialize, deserialize], serializeTestName] of serializers) {
            // eslint-disable-next-line jest/expect-expect
            it(serializeTestName, async function () {
                const handle = await create();
                await validator(handle);

                const serialized = serialize(handle);
                const deserialized = (await (deserialize as any)(serialized)) as T;
                await Promise.all([validator(deserialized), beforeAfterValidator(handle, deserialized)]);
            });
        }
    });
}

interface ToBase64<T> {
    toBase64(this: T, verbose?: boolean): string;
}

interface FromBase64<T> {
    fromBase64(value: string): Promise<T>;
}

interface ToJson<T> {
    toJSON(this: T, verbose?: boolean): Object;
}

interface FromJson<T> {
    fromJSON(value: Object): Promise<T>;
}

/**
 * Construct common serialization and deserialization tests.
 *
 * @param name How to name the parameterized test?
 * @param create A function that constructs the value that is tests. ({@link CryptoSecretKeyHandle})
 * @param constructor The constructor of said value. (`CryptoSecretKeyHandle`)
 * @param validator A function that validates that a value fulfills the specification of its type.
 * @param beforeAfterValidator A function that validates,
 *      that the value before the serialization and deserialization matches the one after.
 */
export function testSerializeDeserializeOfBase64AndJson<T extends ToBase64<T> & ToJson<T>>(
    name: string,
    create: () => Promise<T>,
    constructor: { new (): T } & FromBase64<T> & FromJson<T>,
    validator: (value: T) => Promise<void>,
    beforeAfterValidator: (beforeSerialization: T, afterSerialization: T) => Promise<void>
): void {
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

    commonSerializeTest(name, create, serializers, validator, beforeAfterValidator);
}
