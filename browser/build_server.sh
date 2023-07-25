#!/bin/bash

pnpm run build &&
rm -r ../atomic-server/server/app_assets/ &&
mkdir ../atomic-server/server/app_assets/ &&
cp -r data-browser/dist/ ../atomic-server/server/app_assets/ &&
cp data-browser/tests/e2e.spec.ts ../atomic-server/server/e2e_tests/e2e-generated.spec.ts &&
cp data-browser/tests/testimage.svg ../atomic-server/server/e2e_tests/testimage.svg &&
cp -r data-browser/tests/e2e.spec.ts-snapshots/ ../atomic-server/server/e2e_tests/e2e-generated.spec.ts-snapshots/
