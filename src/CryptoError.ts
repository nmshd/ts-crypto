import { CryptoErrorCode } from "./CryptoErrorCode";

export class CryptoError extends Error {
    public code: string;
    public reason: string;
    public time: string;
    public rootError?: Error;
    public context?: Function;

    public constructor(
        code: string = CryptoErrorCode.Unknown,
        reason = "Crypto operation failed unexpectedly.",
        time: string = new Date().toISOString(),
        rootError?: Error,
        context?: Function
    ) {
        const message = [];
        message.push(code);
        if (reason) {
            message.push(": '", reason, "'");
        }
        if (time) {
            message.push(" at ", time);
        }
        super(message.join(""));
        this.code = code;
        this.reason = reason;
        this.time = time;
        this.name = "CryptoError";
        this.rootError = rootError;
        this.context = context;

        Error.captureStackTrace(this, context ?? CryptoError);
    }

    public setRootError(error: Error): this {
        this.rootError = error;

        return this;
    }

    public setContext(context: Function): this {
        this.context = context;

        Error.captureStackTrace(this, context);

        return this;
    }
}
