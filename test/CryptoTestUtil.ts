import { CoreBuffer } from "@nmshd/crypto";

export class CryptoTestUtil {
    public static isCleared(value: Uint8Array | CoreBuffer): boolean {
        let buffer: Uint8Array;
        if (value instanceof CoreBuffer) {
            buffer = value.buffer;
        } else if (value instanceof Uint8Array) {
            buffer = value;
        } else {
            throw new TypeError("Only Uint8Array and CoreBuffers are allowed values.");
        }
        return buffer.every((element) => {
            return element === 0;
        });
    }
}
