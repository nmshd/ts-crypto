import { type } from "@js-soft/ts-serval";
import { ImportableDerivedBaseKeyHandle } from "./DerivedBaseKeyHandle";

@type("PortableDerivedKeyHandle")
export class PortableDerivedKeyHandle extends ImportableDerivedBaseKeyHandle {
    // Phantom marker to make this type incompatible to other types that extend `BaseKeyHandle`.
    public readonly _isPortableDeriveKeyHandle = true;
}
