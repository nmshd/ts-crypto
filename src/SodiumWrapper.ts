/* eslint-disable @typescript-eslint/naming-convention */
import * as sodium from "libsodium-wrappers-sumo";

export class SodiumWrapper {
    private static _sodium?: Sodium;

    public static get sodium(): Sodium {
        if (!SodiumWrapper._sodium) {
            throw new Error("Sodium is not ready yet. Consider calling `SodiumWrapper.ready()`");
        }

        return SodiumWrapper._sodium;
    }

    public static async ready(): Promise<Sodium> {
        if (SodiumWrapper._sodium) return SodiumWrapper.sodium;
        await sodium.ready;
        const sod2: any = sodium as any;
        SodiumWrapper._sodium = sod2.default as Sodium;
        return SodiumWrapper.sodium;
    }
}

export type Uint8ArrayOutputFormat = "uint8array";

export type StringOutputFormat = "text" | "hex" | "base64";

export type KeyType = "curve25519" | "ed25519" | "x25519";

export enum base64_variants {
    Original,
    OriginalNoPadding,
    UrlSafe,
    UrlSafeNoPadding
}

export interface CryptoBox {
    ciphertext: Uint8Array;
    mac: Uint8Array;
}

export interface StringCryptoBox {
    ciphertext: string;
    mac: string;
}

export interface CryptoKX {
    sharedRx: Uint8Array;
    sharedTx: Uint8Array;
}

export interface StringCryptoKX {
    sharedRx: string;
    sharedTx: string;
}

export interface KeyPair {
    keyType: KeyType;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}

export interface StringKeyPair {
    keyType: KeyType;
    privateKey: string;
    publicKey: string;
}

export interface SecretBox {
    cipher: Uint8Array;
    mac: Uint8Array;
}

export interface StringSecretBox {
    cipher: string;
    mac: string;
}

export interface StateAddress {
    name: string;
}

export interface MessageTag {
    message: Uint8Array;
    tag: number;
}

export interface StringMessageTag {
    message: string;
    tag: number;
}

export interface Sodium {
    add(a: Uint8Array, b: Uint8Array): void;

    compare(b1: Uint8Array, b2: Uint8Array): number;

    crypto_aead_chacha20poly1305_decrypt(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_chacha20poly1305_decrypt(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_chacha20poly1305_decrypt_detached(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_chacha20poly1305_decrypt_detached(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_chacha20poly1305_encrypt(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_chacha20poly1305_encrypt(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_chacha20poly1305_encrypt_detached(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): CryptoBox;
    crypto_aead_chacha20poly1305_encrypt_detached(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringCryptoBox;

    crypto_aead_chacha20poly1305_ietf_decrypt(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_chacha20poly1305_ietf_decrypt(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): CryptoBox;
    crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringCryptoBox;

    crypto_aead_chacha20poly1305_ietf_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_aead_chacha20poly1305_ietf_keygen(outputFormat: StringOutputFormat): string;

    crypto_aead_chacha20poly1305_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_aead_chacha20poly1305_keygen(outputFormat: StringOutputFormat): string;

    crypto_aead_xchacha20poly1305_ietf_decrypt(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        secret_nonce: string | Uint8Array | null,
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        additional_data: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): CryptoBox;
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        message: string | Uint8Array,
        additional_data: string | Uint8Array | null,
        secret_nonce: string | Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringCryptoBox;

    crypto_aead_xchacha20poly1305_ietf_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_keygen(outputFormat: StringOutputFormat): string;

    crypto_auth(
        message: string | Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_auth(message: string | Uint8Array, key: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_auth_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_auth_keygen(outputFormat: StringOutputFormat): string;

    crypto_auth_verify(tag: Uint8Array, message: string | Uint8Array, key: Uint8Array): boolean;

    crypto_box_beforenm(
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_beforenm(publicKey: Uint8Array, privateKey: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_box_detached(
        message: string | Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): CryptoBox;
    crypto_box_detached(
        message: string | Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringCryptoBox;

    crypto_box_easy(
        message: string | Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_easy(
        message: string | Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_box_easy_afternm(
        message: string | Uint8Array,
        nonce: Uint8Array,
        sharedKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_easy_afternm(
        message: string | Uint8Array,
        nonce: Uint8Array,
        sharedKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_box_keypair(outputFormat?: Uint8ArrayOutputFormat | null): KeyPair;
    crypto_box_keypair(outputFormat: StringOutputFormat): StringKeyPair;

    crypto_box_open_detached(
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_open_detached(
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_box_open_easy(
        ciphertext: string | Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_open_easy(
        ciphertext: string | Uint8Array,
        nonce: Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_box_open_easy_afternm(
        ciphertext: string | Uint8Array,
        nonce: Uint8Array,
        sharedKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_open_easy_afternm(
        ciphertext: string | Uint8Array,
        nonce: Uint8Array,
        sharedKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_box_seal(
        message: string | Uint8Array,
        publicKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_seal(message: string | Uint8Array, publicKey: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_box_seal_open(
        ciphertext: string | Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_box_seal_open(
        ciphertext: string | Uint8Array,
        publicKey: Uint8Array,
        privateKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_box_seed_keypair(seed: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): KeyPair;
    crypto_box_seed_keypair(seed: Uint8Array, outputFormat: StringOutputFormat): StringKeyPair;

    crypto_generichash(
        hash_length: number,
        message: string | Uint8Array,
        key?: string | Uint8Array | null,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_generichash(
        hash_length: number,
        message: string | Uint8Array,
        key: string | Uint8Array | null,
        outputFormat: StringOutputFormat
    ): string;

    crypto_generichash_final(
        state_address: StateAddress,
        hash_length: number,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_generichash_final(
        state_address: StateAddress,
        hash_length: number,
        outputFormat: StringOutputFormat
    ): string;

    crypto_generichash_init(key: string | Uint8Array | null, hash_length: number): StateAddress;

    crypto_generichash_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_generichash_keygen(outputFormat: StringOutputFormat): string;

    crypto_generichash_update(state_address: StateAddress, message_chunk: string | Uint8Array): void;

    crypto_hash(message: string | Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_hash(message: string | Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_kdf_derive_from_key(
        subkey_len: number,
        subkey_id: number,
        ctx: string,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_kdf_derive_from_key(
        subkey_len: number,
        subkey_id: number,
        ctx: string,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_kdf_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_kdf_keygen(outputFormat: StringOutputFormat): string;

    crypto_kx_client_session_keys(
        clientPublicKey: Uint8Array,
        clientSecretKey: Uint8Array,
        serverPublicKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): CryptoKX;
    crypto_kx_client_session_keys(
        clientPublicKey: Uint8Array,
        clientSecretKey: Uint8Array,
        serverPublicKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringCryptoKX;

    crypto_kx_keypair(outputFormat?: Uint8ArrayOutputFormat | null): KeyPair;
    crypto_kx_keypair(outputFormat: StringOutputFormat): StringKeyPair;

    crypto_kx_seed_keypair(seed: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): KeyPair;
    crypto_kx_seed_keypair(seed: Uint8Array, outputFormat: StringOutputFormat): StringKeyPair;

    crypto_kx_server_session_keys(
        serverPublicKey: Uint8Array,
        serverSecretKey: Uint8Array,
        clientPublicKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): CryptoKX;
    crypto_kx_server_session_keys(
        serverPublicKey: Uint8Array,
        serverSecretKey: Uint8Array,
        clientPublicKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringCryptoKX;

    crypto_pwhash(
        keyLength: number,
        password: string | Uint8Array,
        salt: Uint8Array,
        opsLimit: number,
        memLimit: number,
        algorithm: number,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_pwhash(
        keyLength: number,
        password: string | Uint8Array,
        salt: Uint8Array,
        opsLimit: number,
        memLimit: number,
        algorithm: number,
        outputFormat: StringOutputFormat
    ): string;

    crypto_pwhash_str(password: string | Uint8Array, opsLimit: number, memLimit: number): string;

    crypto_pwhash_str_verify(hashed_password: string, password: string | Uint8Array): boolean;

    crypto_scalarmult(
        privateKey: Uint8Array,
        publicKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_scalarmult(privateKey: Uint8Array, publicKey: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_scalarmult_base(privateKey: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_scalarmult_base(privateKey: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_secretbox_detached(
        message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): SecretBox;
    crypto_secretbox_detached(
        message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringSecretBox;

    crypto_secretbox_easy(
        message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_secretbox_easy(
        message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_secretbox_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_secretbox_keygen(outputFormat: StringOutputFormat): string;

    crypto_secretbox_open_detached(
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_secretbox_open_detached(
        ciphertext: string | Uint8Array,
        mac: Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_secretbox_open_easy(
        ciphertext: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_secretbox_open_easy(
        ciphertext: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_secretstream_xchacha20poly1305_init_pull(header: Uint8Array, key: Uint8Array): StateAddress;

    crypto_secretstream_xchacha20poly1305_init_push(
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): { state: StateAddress; header: Uint8Array };
    crypto_secretstream_xchacha20poly1305_init_push(
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): { state: StateAddress; header: string };

    crypto_secretstream_xchacha20poly1305_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_secretstream_xchacha20poly1305_keygen(outputFormat: StringOutputFormat): string;

    crypto_secretstream_xchacha20poly1305_pull(
        state_address: StateAddress,
        cipher: string | Uint8Array,
        ad?: string | Uint8Array | null,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): MessageTag;
    crypto_secretstream_xchacha20poly1305_pull(
        state_address: StateAddress,
        cipher: string | Uint8Array,
        ad: string | Uint8Array | null,
        outputFormat: StringOutputFormat
    ): StringMessageTag;

    crypto_secretstream_xchacha20poly1305_push(
        state_address: StateAddress,
        message_chunk: string | Uint8Array,
        ad: string | Uint8Array | null,
        tag: number,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_secretstream_xchacha20poly1305_push(
        state_address: StateAddress,
        message_chunk: string | Uint8Array,
        ad: string | Uint8Array | null,
        tag: number,
        outputFormat: StringOutputFormat
    ): string;

    crypto_secretstream_xchacha20poly1305_rekey(state_address: StateAddress): true;

    crypto_shorthash(
        message: string | Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_shorthash(message: string | Uint8Array, key: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_shorthash_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_shorthash_keygen(outputFormat: StringOutputFormat): string;

    crypto_sign(
        message: string | Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_sign(message: string | Uint8Array, privateKey: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_sign_detached(
        message: string | Uint8Array,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_sign_detached(
        message: string | Uint8Array,
        privateKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_sign_ed25519_pk_to_curve25519(edPk: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_sign_ed25519_pk_to_curve25519(edPk: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_sign_ed25519_sk_to_curve25519(edSk: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_sign_ed25519_sk_to_curve25519(edSk: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_sign_final_create(
        state_address: StateAddress,
        privateKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_sign_final_create(
        state_address: StateAddress,
        privateKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_sign_final_verify(state_address: StateAddress, signature: Uint8Array, publicKey: Uint8Array): boolean;

    crypto_sign_init(): StateAddress;

    crypto_sign_keypair(outputFormat?: Uint8ArrayOutputFormat | null): KeyPair;
    crypto_sign_keypair(outputFormat: StringOutputFormat): StringKeyPair;

    crypto_sign_open(
        signedMessage: string | Uint8Array,
        publicKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_sign_open(
        signedMessage: string | Uint8Array,
        publicKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_sign_seed_keypair(seed: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): KeyPair;
    crypto_sign_seed_keypair(seed: Uint8Array, outputFormat: StringOutputFormat): StringKeyPair;

    crypto_sign_update(state_address: StateAddress, message_chunk: string | Uint8Array): void;

    crypto_sign_verify_detached(signature: Uint8Array, message: string | Uint8Array, publicKey: Uint8Array): boolean;

    from_base64(input: string, variant?: base64_variants): Uint8Array;

    from_hex(input: string): Uint8Array;

    from_string(str: string): Uint8Array;

    increment(bytes: Uint8Array): void;

    is_zero(bytes: Uint8Array): boolean;

    memcmp(b1: Uint8Array, b2: Uint8Array): boolean;

    memzero(bytes: Uint8Array): void;

    output_formats(): (Uint8ArrayOutputFormat | StringOutputFormat)[];

    pad(buf: Uint8Array, blocksize: number): Uint8Array;

    randombytes_buf(length: number, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    randombytes_buf(length: number, outputFormat: StringOutputFormat): string;

    randombytes_buf_deterministic(
        length: number,
        seed: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    randombytes_buf_deterministic(length: number, seed: Uint8Array, outputFormat: StringOutputFormat): string;

    randombytes_close(): void;

    randombytes_random(): number;

    randombytes_stir(): void;

    randombytes_uniform(upper_bound: number): number;

    sodium_version_string(): string;

    symbols(): string[];

    to_base64(input: string | Uint8Array, variant?: base64_variants): string;

    to_hex(input: string | Uint8Array): string;

    to_string(bytes: Uint8Array): string;

    unpad(buf: Uint8Array, blocksize: number): Uint8Array;

    crypto_auth_hmacsha256(
        message: string | Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_auth_hmacsha256(message: string | Uint8Array, key: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_auth_hmacsha256_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_auth_hmacsha256_keygen(outputFormat: StringOutputFormat): string;

    crypto_auth_hmacsha256_verify(tag: Uint8Array, message: string | Uint8Array, key: Uint8Array): boolean;

    crypto_auth_hmacsha512(
        message: string | Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_auth_hmacsha512(message: string | Uint8Array, key: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_auth_hmacsha512_keygen(outputFormat: StringOutputFormat): string;
    crypto_auth_hmacsha512_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;

    crypto_auth_hmacsha512_verify(tag: Uint8Array, message: string | Uint8Array, key: Uint8Array): boolean;

    crypto_box_curve25519xchacha20poly1305_keypair(
        publicKey: Uint8Array,
        secretKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): StringKeyPair;
    crypto_box_curve25519xchacha20poly1305_keypair(
        publicKey: Uint8Array,
        secretKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): KeyPair;

    crypto_box_curve25519xchacha20poly1305_seal(
        message: Uint8Array,
        publicKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;
    crypto_box_curve25519xchacha20poly1305_seal(
        message: Uint8Array,
        publicKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;

    crypto_box_curve25519xchacha20poly1305_seal_open(
        ciphertext: Uint8Array,
        publicKey: Uint8Array,
        secretKey: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;
    crypto_box_curve25519xchacha20poly1305_seal_open(
        ciphertext: Uint8Array,
        publicKey: Uint8Array,
        secretKey: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;

    crypto_core_ristretto255_add(
        p: Uint8Array,
        q: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_add(p: Uint8Array, q: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_from_hash(r: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_core_ristretto255_from_hash(r: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_is_valid_point(point: string | Uint8Array): boolean;

    crypto_core_ristretto255_random(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_core_ristretto255_random(outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_add(
        x: Uint8Array,
        y: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_scalar_add(x: Uint8Array, y: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_complement(
        scalar: string | Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_scalar_complement(scalar: string | Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_invert(
        scalar: string | Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_scalar_invert(scalar: string | Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_mul(
        x: Uint8Array,
        y: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_scalar_mul(x: Uint8Array, y: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_negate(
        scalar: string | Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_scalar_negate(scalar: string | Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_random(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_core_ristretto255_scalar_random(outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_reduce(
        secret: string | Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_scalar_reduce(secret: string | Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_scalar_sub(
        x: Uint8Array,
        y: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_scalar_sub(x: Uint8Array, y: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_core_ristretto255_sub(
        p: Uint8Array,
        q: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_core_ristretto255_sub(p: Uint8Array, q: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_generichash_blake2b_salt_personal(
        subkey_len: number,
        key: string | Uint8Array | null,
        id: Uint8Array,
        ctx: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_generichash_blake2b_salt_personal(
        subkey_len: number,
        key: string | Uint8Array | null,
        id: Uint8Array,
        ctx: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_hash_sha256(message: string | Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_hash_sha256(message: string | Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_hash_sha512(message: string | Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_hash_sha512(message: string | Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_onetimeauth(
        message: string | Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_onetimeauth(message: string | Uint8Array, key: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_onetimeauth_final(state_address: StateAddress, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_onetimeauth_final(state_address: StateAddress, outputFormat: StringOutputFormat): string;

    crypto_onetimeauth_init(key?: string | Uint8Array | null): StateAddress;

    crypto_onetimeauth_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_onetimeauth_keygen(outputFormat: StringOutputFormat): string;

    crypto_onetimeauth_update(state_address: StateAddress, message_chunk: string | Uint8Array): void;

    crypto_onetimeauth_verify(hash: Uint8Array, message: string | Uint8Array, key: Uint8Array): boolean;

    crypto_pwhash_scryptsalsa208sha256(
        keyLength: number,
        password: string | Uint8Array,
        salt: Uint8Array,
        opsLimit: number,
        memLimit: number,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_pwhash_scryptsalsa208sha256(
        keyLength: number,
        password: string | Uint8Array,
        salt: Uint8Array,
        opsLimit: number,
        memLimit: number,
        outputFormat: StringOutputFormat
    ): string;

    crypto_pwhash_scryptsalsa208sha256_ll(
        password: string | Uint8Array,
        salt: string | Uint8Array,
        opsLimit: number,
        r: number,
        p: number,
        keyLength: number,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_pwhash_scryptsalsa208sha256_ll(
        password: string | Uint8Array,
        salt: string | Uint8Array,
        opsLimit: number,
        r: number,
        p: number,
        keyLength: number,
        outputFormat: StringOutputFormat
    ): string;

    crypto_pwhash_scryptsalsa208sha256_str(password: string | Uint8Array, opsLimit: number, memLimit: number): string;

    crypto_pwhash_scryptsalsa208sha256_str_verify(hashed_password: string, password: string | Uint8Array): boolean;

    crypto_scalarmult_ristretto255(scalar: Uint8Array, point: Uint8Array): Uint8Array;

    crypto_scalarmult_ristretto255_base(scalar: Uint8Array): Uint8Array;

    crypto_shorthash_siphashx24(
        message: string | Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_shorthash_siphashx24(
        message: string | Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_sign_ed25519_sk_to_pk(privateKey: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_sign_ed25519_sk_to_pk(privateKey: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_sign_ed25519_sk_to_seed(privateKey: Uint8Array, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_sign_ed25519_sk_to_seed(privateKey: Uint8Array, outputFormat: StringOutputFormat): string;

    crypto_stream_chacha20(
        outLength: number,
        key: Uint8Array,
        nonce: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;
    crypto_stream_chacha20(
        outLength: number,
        key: Uint8Array,
        nonce: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;

    crypto_stream_chacha20_ietf_xor(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_stream_chacha20_ietf_xor(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_stream_chacha20_ietf_xor_ic(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        nonce_increment: number,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_stream_chacha20_ietf_xor_ic(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        nonce_increment: number,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_stream_chacha20_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_stream_chacha20_keygen(outputFormat: StringOutputFormat): string;

    crypto_stream_chacha20_xor(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_stream_chacha20_xor(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_stream_chacha20_xor_ic(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        nonce_increment: number,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_stream_chacha20_xor_ic(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        nonce_increment: number,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_stream_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_stream_keygen(outputFormat: StringOutputFormat): string;

    crypto_stream_xchacha20_keygen(outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
    crypto_stream_xchacha20_keygen(outputFormat: StringOutputFormat): string;

    crypto_stream_xchacha20_xor(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_stream_xchacha20_xor(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;

    crypto_stream_xchacha20_xor_ic(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        nonce_increment: number,
        key: Uint8Array,
        outputFormat?: Uint8ArrayOutputFormat | null
    ): Uint8Array;
    crypto_stream_xchacha20_xor_ic(
        input_message: string | Uint8Array,
        nonce: Uint8Array,
        nonce_increment: number,
        key: Uint8Array,
        outputFormat: StringOutputFormat
    ): string;
}
