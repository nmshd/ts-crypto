import { type } from "@js-soft/ts-serval";
import { CoreBuffer } from "../../CoreBuffer";
import { BaseKeyHandle, IBaseKeyHandleSerialized } from "./BaseKeyHandle";

@type("PortableDerivedKeyHandle")
export class PortableDerivedKeyHandle extends BaseKeyHandle {
    public readonly _isPortableDeriveKeyHandle = true;

    public override toJSON(verbose = true): IBaseKeyHandleSerialized {
        return {
            kid: this.id,
            pnm: this.providerName,
            spc: this.spec,
            "@type": verbose ? "PortableDerivedKeyHandle" : undefined
        };
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }
}
