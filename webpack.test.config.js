const path = require("path");

module.exports = {
    mode: "development",
    node: {
        global: false
    },
    entry: {
        "nmshd.crypto.test": "./dist-test/index"
    },
    output: {
        path: path.resolve(__dirname, "lib-web"),
        filename: "[name].js",
        library: "NMSHDCryptoTest",
        umdNamedDefine: true
    },
    resolve: {
        extensions: [".js", ".json"]
    },
    devtool: "source-map",
    externals: {
        "../src": "NMSHDCrypto",
        "../../src": "NMSHDCrypto",
        "./tmp-browser/src": "NMSHDCrypto",
        "./src": "NMSHDCrypto",
        "@nmshd": "NMSHDCrypto",
        chai: "chai",
        "@nmshd/crypto": "NMSHDCrypto",
        "@js-soft/ts-serval": "TSServal"
    }
};
