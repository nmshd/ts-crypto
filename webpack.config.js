const path = require("path");
const CopyWebpackPlugin = require("copy-webpack-plugin");

module.exports = {
    mode: "development",
    node: {
        global: false
    },
    plugins: [
        new CopyWebpackPlugin({
            patterns: [{ from: "./node_modules/@js-soft/ts-serval/lib-web" }]
        })
    ],
    entry: {
        "nmshd.crypto": "./dist/index"
    },
    output: {
        path: path.resolve(__dirname, "lib-web"),
        filename: "[name].js",
        library: "NMSHDCrypto",
        umdNamedDefine: true
    },
    resolve: {
        extensions: [".js", ".json"]
    },
    devtool: "source-map",
    optimization: {},
    externals: {
        chai: "chai",
        "@nmshd/crypto": "NMSHDCrypto",
        path: "NMSHDCrypto",
        crypto: "NMSHDCrypto",
        "@js-soft/ts-serval": "TSServal"
    }
};
