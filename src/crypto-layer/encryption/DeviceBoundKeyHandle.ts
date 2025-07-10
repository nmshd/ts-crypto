import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { BaseKeyHandle, IBaseKeyHandle, IBaseKeyHandleSerialized } from "./BaseKeyHandle";

/** Key handle that is non exportable (the key cannot be extracted). */
@type("DeviceBoundKeyHandle")
export class DeviceBoundKeyHandle extends BaseKeyHandle {
    // Phantom marker to make this type incompatible to other types that extend `BaseKeyHandle`.
    public readonly _isDeviceBoundKeyHandle = true;

    public override toJSON(verbose = true): IBaseKeyHandleSerialized {
        return {
            kid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "DeviceBoundKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Deserializes an object representation of a {@link DeviceBoundKeyHandle}.
     *
     * This method is not able to import raw keys or {@link KeyHandle}.
     */
    public static async from(value: IBaseKeyHandle | CoreBuffer): Promise<DeviceBoundKeyHandle> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromJSON(value: IBaseKeyHandleSerialized): Promise<DeviceBoundKeyHandle> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromBase64(value: string): Promise<DeviceBoundKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
