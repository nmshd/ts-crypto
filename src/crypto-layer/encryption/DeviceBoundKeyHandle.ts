import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { BaseKeyHandle, IBaseKeyHandleSerialized } from "./BaseKeyHandle";

/** Key handle that is non exportable (the key cannot be extracted). */
@type("DeviceBoundKeyHandle")
export class DeviceBoundKeyHandle extends BaseKeyHandle {
    // Phantom marker to make this type incompatible to other types that extend `BaseKeyHandle`.
    public readonly _isDeviceBoundKeyHandle = true;

    public override toJSON(verbose = true): IBaseKeyHandleSerialized {
        return {
            kid: this.id,
            pnm: this.providerName,
            spc: this.spec,
            "@type": verbose ? "DeviceBoundKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }
}
