#!/usr/bin/env bash
set -e

if [ -z "$(which jq)" ]; then
    echo "jq could not be found"
    exit 1
fi

if [ -z "$VERSION" ]; then
    echo "The environment variable 'VERSION' must be set."
    exit 1
fi

if [ -z "$BUILD_NUMBER" ]; then
    echo "The environment variable 'BUILD_NUMBER' must be set."
    exit 1
fi

if [ -z "$COMMIT_HASH" ]; then
    echo "The environment variable 'COMMIT_HASH' must be set."
    exit 1
fi

DEPENDENCIES=$(jq .dependencies package.json -cr)
if [ "$DEPENDENCIES" = "null" ]; then
    DEPENDENCIES="{}"
fi

DEPENDENCIES="${DEPENDENCIES//[\/]/\\/}" # replace '/' with '\/' because it's a special char

DATE=$(date -u --iso-8601=seconds)

echo "Writing the following properties into $TARGET_FILE"
echo "  - DEPENDENCIES: $DEPENDENCIES"
echo "  - VERSION: $VERSION"
echo "  - BUILD_NUMBER: $BUILD_NUMBER"
echo "  - COMMIT_HASH: $COMMIT_HASH"
echo "  - DATE: $DATE"

TARGET_FILE="./dist/buildInformation.js"

sed -i "s/\"{{dependencies}}\"/"$DEPENDENCIES"/" $TARGET_FILE
sed -i "s/{{version}}/$VERSION/" $TARGET_FILE
sed -i "s/{{build}}/$BUILD_NUMBER/" $TARGET_FILE
sed -i "s/{{commit}}/$COMMIT_HASH/" $TARGET_FILE
sed -i "s/{{date}}/$DATE/" $TARGET_FILE
