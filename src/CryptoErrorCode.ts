export enum CryptoErrorCode {
    NotYetImplemented = "error.crypto.notYetImplemented",
    Unknown = "error.crypto.unknown",

    PasswordInsecure = "error.crypto.insecurePassword",
    WrongLength = "error.crypto.wrongLength",
    WrongParameters = "error.crypto.wrongMaximum",

    BufferAdd = "error.crypto.bufferAdd",

    WrongObject = "error.crypto.wrongObject",
    WrongBuffer = "error.crypto.wrongBuffer",
    WrongSerializedBuffer = "error.crypto.wrongSerializedBuffer",
    WrongHashAlgorithm = "error.crypto.hash.wrongHashAlgorithm",
    WrongId = "error.crypto.wrongId",

    EncryptionWrongAlgorithm = "error.crypto.wrongEncryptionAlgorithm",
    EncryptionWrongPlaintext = "error.crypto.encryption.wrongPlaintext",
    EncryptionWrongCipher = "error.crypto.encryption.wrongCipher",
    EncryptionWrongSecretKey = "error.crypto.encryption.wrongSecretKey",
    EncryptionWrongNonce = "error.crypto.encryption.wrongNonce",
    EncryptionWrongCounter = "error.crypto.encryption.wrongCounter",
    EncryptionKeyGeneration = "error.crypto.encryption.keyGeneration",
    EncryptionEncrypt = "error.crypto.encryption.encrypt",
    EncryptionDecrypt = "error.crypto.encryption.decrypt",
    EncryptionNoNonceNorCounter = "error.crypto.validation.noNonceNorCounter",
    EncryptionNonceAndCounter = "error.crypto.validation.nonceAndCounter",

    ExchangeKeyGeneration = "error.crypto.exchange.keyGeneration",
    ExchangeKeyDerivation = "error.crypto.exchange.keyDerivation",
    ExchangeWrongAlgorithm = "error.crypto.exchange.wrongExchangeAlgorithm",
    ExchangeWrongPrivateKey = "error.crypto.exchange.wrongPrivateKey",
    ExchangeWrongPublicKey = "error.crypto.exchange.wrongPublicKey",

    RelationshipNoPeer = "error.crypto.relationship.noPeer",
    RelationshipNoRequestorNorTemplator = "error.crypto.relationships.noRequestorNorTemplator",

    SignatureKeyGeneration = "error.crypto.signature.keyGeneration",
    SignatureWrongAlgorithm = "error.crypto.signature.wrongAlgorithm",
    SignatureWrongPrivateKey = "error.crypto.signature.wrongPrivateKey",
    SignatureWrongPublicKey = "error.crypto.signature.wrongPublicKey",
    SignatureSign = "error.crypto.signature.sign",
    SignatureVerify = "error.crypto.signature.verify",

    StateWrongSecretKey = "error.crypto.state.wrongSecretKey",
    StateWrongNonce = "error.crypto.state.wrongNonce",
    StateWrongCounter = "error.crypto.state.wrongCounter",
    StateWrongOrder = "error.crypto.state.orderDoesNotMatch",
    StateWrongType = "error.crypto.state.wrongType"
}
