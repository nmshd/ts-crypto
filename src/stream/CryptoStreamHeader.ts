import { ISerializable, Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, ICoreBuffer } from "../CoreBuffer";

export interface ICryptoStreamHeader extends ISerializable {
    header: ICoreBuffer;
}

export interface ICryptoStreamHeaderStatic {
    new (): ICryptoStreamHeader;
    from(obj: ICryptoStreamHeader): Promise<ICryptoStreamHeader>;
    deserialize(content: string): Promise<ICryptoStreamHeader>;
}

@type("CryptoStreamHeader")
export class CryptoStreamHeader extends Serializable implements ICryptoStreamHeader {
    @validate()
    @serialize()
    public header: CoreBuffer;

    public override toString(): string {
        return this.serialize();
    }

    public override serialize(): string {
        const obj = this.toJSON();
        return JSON.stringify(obj);
    }

    public override toJSON(): Object {
        const obj = {
            "@type": "CryptoStreamHeader",
            header: this.header.toBase64()
        };
        return obj;
    }

    public toBase64(): string {
        return this.header.toBase64();
    }

    protected static override preFrom(value: any): any {
        if (value instanceof CoreBuffer) {
            return { header: value };
        }

        return value;
    }

    public static from(obj: ICryptoStreamHeader | CoreBuffer): CryptoStreamHeader {
        return this.fromAny(obj);
    }

    public static fromBase64(value: string): CryptoStreamHeader {
        const buffer = CoreBuffer.fromBase64(value);
        return this.from({ header: buffer });
    }
}
