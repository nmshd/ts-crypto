import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { BaseKeyHandle, IBaseKeyHandleSerialized } from "./BaseKeyHandle";

/** Key handle that is exportable and can also be created by importing a key. */
@type("PortableKeyHandle")
export class PortableKeyHandle extends BaseKeyHandle {
    // Phantom marker to make this type incompatible to other types that extend `BaseKeyHandle`.
    public readonly _isPortableKeyHandle = true;

    public override toJSON(verbose = true): IBaseKeyHandleSerialized {
        return {
            kid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "PortableKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Deserializes an object representation of a {@link PortableKeyHandle}.
     *
     * This method is not able to import raw keys or {@link KeyHandle}.
     */
    public static async from(value: IBaseKeyHandleSerialized | CoreBuffer): Promise<PortableKeyHandle> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromJSON(value: IBaseKeyHandleSerialized): Promise<PortableKeyHandle> {
        return await this.fromAny(value);
    }

    /** @see from */
    public static async fromBase64(value: string): Promise<PortableKeyHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
