const path = require("path");
const TerserPlugin = require("terser-webpack-plugin");

module.exports = {
    mode: "production",
    node: {
        global: false
    },
    entry: {
        "nmshd.crypto.min": "./dist/index"
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
    optimization: {
        minimize: true,
        minimizer: [
            new TerserPlugin({
                terserOptions: {
                    keep_classnames: true,
                    keep_fnames: true
                }
            })
        ]
    },
    externals: {
        chai: "chai",
        "@nmshd/crypto": "NMSHDCrypto",
        path: "NMSHDCrypto",
        crypto: "NMSHDCrypto",
        "@js-soft/ts-serval": "TSServal"
    }
};
