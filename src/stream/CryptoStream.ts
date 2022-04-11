import {
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_PUSH
} from "libsodium-wrappers-sumo";
import { CoreBuffer, ICoreBuffer } from "../CoreBuffer";
import { SodiumWrapper, StateAddress } from "../SodiumWrapper";
import { CryptoStreamAddress } from "./CryptoStreamAddress";
import { CryptoStreamHeader } from "./CryptoStreamHeader";
import { CryptoStreamState } from "./CryptoStreamState";

export interface ICryptoStream {}

export interface ICryptoStreamStatic {
    new (): ICryptoStream;
}

function staticImplements<T>() {
    return <U extends T>(_constructor: U) => {
        // No need for an implementation. This decorator is only for compile time. By saying `U extends T`,
        // TypeScript checks whether the constructor implements the given interface.
    };
}

export enum CryptoStreamTag {
    // eslint-disable-next-line @typescript-eslint/prefer-literal-enum-member
    Message = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    // eslint-disable-next-line @typescript-eslint/prefer-literal-enum-member
    Push = crypto_secretstream_xchacha20poly1305_TAG_PUSH,
    // eslint-disable-next-line @typescript-eslint/prefer-literal-enum-member
    Final = crypto_secretstream_xchacha20poly1305_TAG_FINAL
}

@staticImplements<ICryptoStreamStatic>()
export class CryptoStream implements ICryptoStream {
    public static async initServer(key: CoreBuffer): Promise<CryptoStreamState> {
        const sodium = await SodiumWrapper.ready();
        const stream = sodium.crypto_secretstream_xchacha20poly1305_init_push(key.buffer);
        const headerBuffer = CoreBuffer.from(stream.header);
        return CryptoStreamState.from({
            address: CryptoStreamAddress.from(stream.state as unknown as string),
            header: CryptoStreamHeader.from(headerBuffer)
        });
    }

    public static async initClient(header: CryptoStreamHeader, key: CoreBuffer): Promise<CryptoStreamAddress> {
        const sodium = await SodiumWrapper.ready();
        const stream = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header.header.buffer, key.buffer);

        return CryptoStreamAddress.from(stream as any);
    }

    public static async encrypt(message: ICoreBuffer, stream: CryptoStreamAddress): Promise<CoreBuffer> {
        const sodium = await SodiumWrapper.ready();

        const cipher = sodium.crypto_secretstream_xchacha20poly1305_push(
            stream.address as unknown as StateAddress,
            message.buffer,
            null,
            crypto_secretstream_xchacha20poly1305_TAG_PUSH
        );

        return new CoreBuffer(cipher);
    }

    public static async decrypt(cipher: ICoreBuffer, stream: CryptoStreamAddress): Promise<CoreBuffer> {
        const sodium = await SodiumWrapper.ready();

        const message = sodium.crypto_secretstream_xchacha20poly1305_pull(
            stream.address as unknown as StateAddress,
            cipher.buffer
        );

        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!message) {
            throw new Error("Something went wrong while decrypting the message");
        }
        return new CoreBuffer(message.message);
    }

    protected static async getState(address: number): Promise<CoreBuffer> {
        const sodium = (await SodiumWrapper.ready()) as any;

        const start = address;
        const length = sodium.libsodium._crypto_secretstream_xchacha20poly1305_statebytes();
        const buffer = sodium.libsodium.HEAP8.slice(start, start + length);
        return new CoreBuffer(new Uint8Array(buffer));
    }

    protected static async setState(address: number, state: CoreBuffer): Promise<void> {
        const sodium = (await SodiumWrapper.ready()) as any;

        const start = address;
        const length = sodium.libsodium._crypto_secretstream_xchacha20poly1305_statebytes();
        if (state.buffer.byteLength !== length) {
            throw new Error(
                `Input state is ${state.buffer.byteLength} bytes long, whereas statebytes must be ${length} bytes!`
            );
        }
        sodium.libsodium.HEAP8.set(new Int8Array(state.buffer), start);
    }
}
