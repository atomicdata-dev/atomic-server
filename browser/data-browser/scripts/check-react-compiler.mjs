import { resolve } from 'node:path';
import { checkFile, compilerVersion } from './react-compiler.mjs';

const args = process.argv.slice(2);
const verbose = args.includes('--verbose');
const files = args.filter(arg => arg !== '--verbose');

if (files.length === 0 || files.includes('--help')) {
  console.info(`Usage: node browser/data-browser/scripts/check-react-compiler.mjs [--verbose] <file> [file ...]

Paths are relative to the current directory (absolute paths also work).
Uses the app's installed oxc-transform-react with React 19 / automatic JSX.
Prints compiler diagnostics with source locations. Exits 1 on any diagnostic,
fatal transform or unreadable file; exits 0 otherwise.
Default: file:line:column and message. Use --verbose for source code frames.

Memoization is reported per file. It does not prove every function was memoized;
an explicit "use no memo" or ineligible function may be skipped silently.
This checks compiler compatibility, not TypeScript types or runtime behavior.`);
  process.exit(files.length === 0 ? 1 : 0);
}

console.info(`oxc-transform-react ${compilerVersion} (React 19)`);

for (const file of files) {
  const filename = resolve(file);

  try {
    if (!/\.[cm]?[jt]sx?$/.test(filename)) {
      throw new Error('Expected a JavaScript or TypeScript source file.');
    }

    const result = checkFile(filename, verbose);

    if (result.diagnostics.length > 0) {
      process.exitCode = 1;
      console.error(result.diagnostics.join('\n'));
    } else {
      console.info(
        `OK ${filename}: no diagnostics; ${result.memoized ? 'memoization emitted' : 'no memoization emitted (check eligibility / opt-outs)'}.`,
      );
    }
  } catch (error) {
    process.exitCode = 1;
    console.error(`FAIL ${filename}: ${error.message}`);
  }
}
