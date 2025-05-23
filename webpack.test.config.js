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
        extensions: [".js", ".json"],
        alias: {
            "@nmshd/crypto": __dirname
        }
    },
    devtool: "source-map",
    externals: {
        chai: "chai",
        path: "NMSHDCrypto",
        crypto: "NMSHDCrypto"
    }
};
