import { ISerializableAsync, ISerialized, SerializableAsync, type } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoStateType } from "./CryptoStateType";

export interface ICryptoPublicStateSerialized extends ISerialized {
    nnc: string;
    alg: number;
    id?: string;
    typ: number;
}

export interface ICryptoPublicState extends ISerializableAsync {
    nonce: CoreBuffer;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

@type("CryptoPublicState")
export class CryptoPublicState extends SerializableAsync implements ICryptoPublicState, IClearable {
    private readonly _id?: string;
    public get id(): string | undefined {
        return this._id;
    }
    private readonly _nonce: CoreBuffer;
    public get nonce(): CoreBuffer {
        return this._nonce;
    }
    private readonly _algorithm: CryptoEncryptionAlgorithm;
    public get algorithm(): CryptoEncryptionAlgorithm {
        return this._algorithm;
    }
    private readonly _stateType: CryptoStateType;
    public get stateType(): CryptoStateType {
        return this._stateType;
    }

    public constructor(
        nonce: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm,
        stateType: CryptoStateType,
        id?: string
    ) {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);
        CryptoValidation.checkNonceForAlgorithm(nonce, algorithm);

        CryptoValidation.checkStateType(stateType);

        super();

        this._nonce = nonce;
        this._algorithm = algorithm;
        this._id = id;
        this._stateType = stateType;
    }

    public clear(): void {
        this.nonce.clear();
    }

    public toJSON(verbose = true): ICryptoPublicStateSerialized {
        const obj: ICryptoPublicStateSerialized = {
            nnc: this.nonce.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType
        };
        if (this.id) {
            obj.id = this.id;
        }
        if (verbose) {
            obj["@type"] = "CryptoPublicState";
        }
        return obj;
    }

    public static from(value: CryptoPublicState | ICryptoPublicState): Promise<CryptoPublicState> {
        return Promise.resolve(new CryptoPublicState(value.nonce, value.algorithm, value.stateType, value.id));
    }

    public static fromJSON(value: ICryptoPublicStateSerialized): Promise<CryptoPublicState> {
        let error;
        error = CryptoValidation.checkEncryptionAlgorithm(value.alg);
        if (error) throw error;

        error = CryptoValidation.checkStateType(value.typ);
        if (error) throw error;

        error = CryptoValidation.checkNonceAsString(value.nnc, value.alg as CryptoEncryptionAlgorithm);
        if (error) throw error;

        const buffer = CoreBuffer.fromBase64URL(value.nnc);
        return Promise.resolve(
            new CryptoPublicState(
                buffer,
                value.alg as CryptoEncryptionAlgorithm,
                value.typ as CryptoStateType,
                value.id
            )
        );
    }

    public static async fromBase64(value: string): Promise<CryptoPublicState> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public static async deserialize(value: string): Promise<CryptoPublicState> {
        return await this.fromJSON(JSON.parse(value));
    }
}
