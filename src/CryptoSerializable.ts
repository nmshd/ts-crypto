import { ISerializable, ISerializableAsync, Serializable, SerializableAsync } from "@js-soft/ts-serval";
import { CoreBuffer } from "./CoreBuffer";

export abstract class CryptoSerializable extends Serializable implements ISerializable {
    public override serialize(verbose = true): string {
        return JSON.stringify(this.toJSON(verbose));
    }

    public toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }
}

export abstract class CryptoSerializableAsync extends SerializableAsync implements ISerializableAsync {
    public override serialize(verbose = true): string {
        return JSON.stringify(this.toJSON(verbose));
    }

    public toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }
}