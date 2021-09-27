import { ISerializableAsync, ISerialized, SerializableAsync } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPublicState } from "./CryptoPublicState";
import { CryptoStateType } from "./CryptoStateType";

export interface ICryptoPrivateStateSerialized extends ISerialized {
    key: string;
    nnc: string;
    cnt: number;
    alg: number;
    id?: string;
    typ: number;
}

export interface ICryptoPrivateState extends ISerializableAsync {
    secretKey: ICoreBuffer;
    nonce: ICoreBuffer;
    counter: number;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

export class CryptoPrivateState extends SerializableAsync implements ICryptoPrivateState, IClearable {
    private readonly _id?: string;
    public get id(): string | undefined {
        return this._id;
    }
    private readonly _nonce: CoreBuffer;
    public get nonce(): CoreBuffer {
        return this._nonce;
    }
    private _counter: number;
    public get counter(): number {
        return this._counter;
    }
    private readonly _secretKey: CoreBuffer;
    public get secretKey(): CoreBuffer {
        return this._secretKey;
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
        counter: number,
        secretKey: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm,
        stateType: CryptoStateType,
        id?: string
    ) {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);
        CryptoValidation.checkCounter(counter);
        CryptoValidation.checkNonceForAlgorithm(nonce, algorithm);
        CryptoValidation.checkSecretKeyForAlgorithm(secretKey, algorithm);
        CryptoValidation.checkStateType(stateType);

        if (id) {
            CryptoValidation.checkId(id);
        }

        super();

        this._nonce = nonce;
        this._counter = counter ? counter : 0;
        this._secretKey = secretKey;
        this._algorithm = algorithm;
        this._stateType = stateType;
        this._id = id;
    }

    protected setCounter(value: number): void {
        this._counter = value;
    }

    public clear(): void {
        this.secretKey.clear();
        this.nonce.clear();
    }

    public toString(): string {
        return this.serialize();
    }

    public serialize(): string {
        const obj = this.toJSON();
        return JSON.stringify(obj);
    }

    public toPublicState(): CryptoPublicState {
        return new CryptoPublicState(this.nonce.clone(), this.algorithm, this.stateType, this.id);
    }

    public toJSON(verbose = true): ICryptoPrivateStateSerialized {
        const obj: ICryptoPrivateStateSerialized = {
            nnc: this.nonce.toBase64URL(),
            cnt: this.counter,
            key: this.secretKey.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType
        };
        if (this.id) {
            obj.id = this.id;
        }
        if (verbose) {
            obj["@type"] = "CryptoPrivateState";
        }
        return obj;
    }

    public static from(obj: CryptoPrivateState | ICryptoPrivateState): Promise<CryptoPrivateState> {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!obj.secretKey) {
            throw new CryptoError(CryptoErrorCode.StateWrongSecretKey, "No secretKey property set.");
        }
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!obj.nonce) {
            throw new CryptoError(CryptoErrorCode.StateWrongNonce, "No nonce nor counter property set.");
        }
        if (typeof obj.counter === "undefined") {
            throw new CryptoError(CryptoErrorCode.StateWrongCounter, "Wrong counter.");
        }

        return Promise.resolve(
            new CryptoPrivateState(
                CoreBuffer.from(obj.nonce),
                obj.counter,
                CoreBuffer.from(obj.secretKey),
                obj.algorithm,
                obj.stateType,
                obj.id
            )
        );
    }

    public static fromJSON(value: ICryptoPrivateStateSerialized): Promise<CryptoPrivateState> {
        CryptoValidation.checkEncryptionAlgorithm(value.alg);
        CryptoValidation.checkCounter(value.cnt);
        CryptoValidation.checkSerializedBuffer(value.nnc, 0, 24, "nonce");
        CryptoValidation.checkSerializedSecretKeyForAlgorithm(value.key, value.alg as CryptoEncryptionAlgorithm);
        if (value.typ) {
            CryptoValidation.checkStateType(value.typ);
        }
        const nonceBuffer = CoreBuffer.fromBase64URL(value.nnc);
        const secretKeyBuffer = CoreBuffer.fromBase64URL(value.key);
        return Promise.resolve(
            new CryptoPrivateState(
                nonceBuffer,
                value.cnt,
                secretKeyBuffer,
                value.alg as CryptoEncryptionAlgorithm,
                value.typ as CryptoStateType,
                value.id
            )
        );
    }

    public static async deserialize(value: string): Promise<CryptoPrivateState> {
        const obj = JSON.parse(value);
        return await this.from(obj);
    }
}
