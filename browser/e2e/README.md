# Atomic Data Browser E2E tests

We use `playwright` to run end-to-end tests in the browser.

```sh
# install deps
bun i
# install chromium
bun playwright-install
# run all tests, creates a `playwright-report` folder with HTML files + images
bun test-e2e
# run all tests and updates snapshots
bun test-update
# run all tests in debug mode
bun test-debug
# run a single test (e.g. 'table')
bun test-query table
# create a new test
bun test-new
# deploy report to netlify
netlify deploy --dir playwright-report --prod --site atomic-tests
```
