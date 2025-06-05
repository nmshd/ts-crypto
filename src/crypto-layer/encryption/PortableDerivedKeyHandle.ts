import { type } from "@js-soft/ts-serval";
import { ImportableBaseDerivedKeyHandle } from "./BaseDerivedKeyHandle";

@type("PortableDerivedKeyHandle")
export class PortableDerivedKeyHandle extends ImportableBaseDerivedKeyHandle {
    // Phantom marker to make this type incompatible to other types that extend `BaseKeyHandle`.
    public readonly _isPortableDeriveKeyHandle = true;
}
