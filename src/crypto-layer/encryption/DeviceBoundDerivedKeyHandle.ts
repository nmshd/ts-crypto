import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { BaseKeyHandle, IBaseKeyHandleSerialized } from "./BaseKeyHandle";

/** Non exportable, ephemeral key handle that is derived from a device bound key handle. */
@type("DeviceBoundDerivedKeyHandle")
export class DeviceBoundDerivedKeyHandle extends BaseKeyHandle {
    // Phantom marker to make this type incompatible to other types that extend `BaseKeyHandle`.
    public readonly _isDeviceBoundDerivedKeyHandle = true;

    public override toJSON(verbose = true): IBaseKeyHandleSerialized {
        return {
            kid: this.id,
            pnm: this.providerName,
            "@type": verbose ? "DeviceBoundDerivedKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }
}
