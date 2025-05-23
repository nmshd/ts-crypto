# Development

Careful: Please do not use absolute imports ("src/CoreBuffer") which might be the default in your
development environment. Doing so conflicts with ts-node, resulting in failures. Use
relative imports (e.g. "../CoreBuffer") instead.

## Build

To trigger a complete build run:
`npm run build`

## Testing

To trigger a complete test, tun:
`npm run test`

Careful: You have to build the the complete package first in order to test the browser
tests completely. Thus, please run `npm run build` before an `npm run test`.

Careful: Ensure that Test Sources include any Crypto Library content from "@nmshd/crypto" -
and NOT "../src/..." which might be the default include in your environment. This works for
ts-node and all Tests are green on NodeJS, but in the browser environment, this will break
the tests. The tests are testing the created library assets (built by webpack), the separately
included class from within the test file is NOT part of the library bundle. This results into
having two separate class declarations of the same class (e.g. test1.CoreBuffer and
crypto1.CoreBuffer) within the browser environment.

If there are errors within the browser context, you can start the browser environment manually
by running:
`npm run test:server`

Afterwards, open your browser and enter
`http://localhost:7777/test-browser/index_manual.html`

To start the test, type "mocha.run()" into the browser's console.
