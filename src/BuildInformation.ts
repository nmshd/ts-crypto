import { buildInformation as servalBuildInformation } from "@js-soft/ts-serval";

export default {
    version: "{{version}}",
    build: "{{build}}",
    date: "{{date}}",
    commit: "{{commit}}",
    dependencies: "{{dependencies}}",
    libraries: {
        serval: servalBuildInformation
    }
};
