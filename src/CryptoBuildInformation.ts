import { ServalBuildInformation } from "@js-soft/ts-serval";

const buildInformation = {
    version: "{{version}}",
    date: "{{date}}",
    commit: "{{commit}}",
    dependencies: {},
    serval: ServalBuildInformation.info
};

try {
    buildInformation.dependencies = JSON.parse(`{{dependencies}}`); // eslint-disable-line @typescript-eslint/quotes
} catch (e) {
    // Leave the default value
}

export default buildInformation;
