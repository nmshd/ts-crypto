set -e

npm ci
npm run lint:prettier
npm run lint:eslint
npx license-check
npx better-npm-audit audit
