import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { IBaseKeyHandleSerialized, ImportableBaseKeyHandle } from "./BaseKeyHandle";

/** Key handle that is exportable and can also be created by importing a key. */
@type("PortableKeyHandle")
export class PortableKeyHandle extends ImportableBaseKeyHandle {
    public readonly _isPortableKeyHandle = true;

    public override toJSON(verbose = true): IBaseKeyHandleSerialized {
        return {
            kid: this.id,
            pnm: this.providerName,
            spc: this.spec,
            "@type": verbose ? "PortableKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }
}
