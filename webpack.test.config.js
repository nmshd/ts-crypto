const path = require("path");
const { IgnorePlugin } = require("webpack");
/* const { plugins } = require("./webpack.config"); */

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
    },
    plugins: [new IgnorePlugin({ resourceRegExp: /rs\-crypto\-node/g })]
};
