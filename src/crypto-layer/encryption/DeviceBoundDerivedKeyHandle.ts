import { type } from "@js-soft/ts-serval";
import { DerivedBaseKeyHandle } from "./DerivedBaseKeyHandle";

/** Non exportable, ephemeral key handle that is derived from a device bound key handle. */
@type("DeviceBoundDerivedKeyHandle")
export class DeviceBoundDerivedKeyHandle extends DerivedBaseKeyHandle {
    // Phantom marker to make this type incompatible to other types that extend `BaseKeyHandle`.
    public readonly _isDeviceBoundDerivedKeyHandle = true;
}
