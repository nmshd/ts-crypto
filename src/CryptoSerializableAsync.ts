import { ISerializableAsync, SerializableAsync, type } from "@js-soft/ts-serval";
import { CoreBuffer } from "./CoreBuffer";

@type("CryptoSerializableAsync")
export class CryptoSerializableAsync extends SerializableAsync implements ISerializableAsync {
    public serialize(verbose = true): string {
        return JSON.stringify(this.toJSON(verbose));
    }

    public toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }
}
